from __future__ import annotations

import ast
import base64
import json
import keyword
import queue
import socketserver
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

_BOOTSTRAP = r'''
import ast as _dspy_ast
import base64 as _dspy_base64
import contextlib as _dspy_contextlib
import io as _dspy_io
import json as _dspy_json
import socket as _dspy_socket

class _DSPySubmission(BaseException):
    def __init__(self, value):
        self.value = value

def _dspy_host_call(name, args, kwargs):
    request = _dspy_json.dumps({
        "token": _dspy_interpreters_token,
        "name": name,
        "args": args,
        "kwargs": kwargs,
    }) + "\n"
    with _dspy_socket.create_connection((_dspy_interpreters_host, _dspy_interpreters_port)) as connection:
        stream = connection.makefile("rw", encoding="utf-8")
        stream.write(request)
        stream.flush()
        response = _dspy_json.loads(stream.readline())
    if not response["ok"]:
        raise RuntimeError(response["error"])
    return response["value"]

def _dspy_bind(tool_names, output_fields):
    global _dspy_capabilities, _dspy_output_fields
    for old_name in _dspy_capabilities:
        globals().pop(old_name, None)
    _dspy_capabilities = set(tool_names)
    _dspy_output_fields = output_fields
    for tool_name in tool_names:
        def tool(*args, __name=tool_name, **kwargs):
            return _dspy_host_call(__name, args, kwargs)
        tool.__name__ = tool_name
        globals()[tool_name] = tool

    def submit(*args, **kwargs):
        if _dspy_output_fields is None:
            if len(args) != 1 or kwargs:
                raise TypeError("SUBMIT requires one output value")
            value = {"output": args[0]}
        else:
            names = [field["name"] for field in _dspy_output_fields]
            if args and kwargs:
                raise TypeError("SUBMIT accepts positional or keyword values, not both")
            value = dict(zip(names, args)) if args else dict(kwargs)
            if set(value) != set(names):
                raise TypeError("SUBMIT fields do not match the configured output fields")
        raise _DSPySubmission(value)
    globals()["SUBMIT"] = submit

def _dspy_execute(code_b64, variables_b64, tool_names, output_fields):
    _dspy_bind(tool_names, output_fields)
    variables = _dspy_json.loads(_dspy_base64.b64decode(variables_b64))
    globals().update(variables)
    captured = _dspy_io.StringIO()
    try:
        tree = _dspy_ast.parse(_dspy_base64.b64decode(code_b64).decode("utf-8"), mode="exec")
        with _dspy_contextlib.redirect_stdout(captured), _dspy_contextlib.redirect_stderr(captured):
            value = None
            if tree.body and isinstance(tree.body[-1], _dspy_ast.Expr):
                prefix = _dspy_ast.Module(body=tree.body[:-1], type_ignores=[])
                exec(compile(prefix, "<interpreter>", "exec"), globals())
                value = eval(compile(_dspy_ast.Expression(tree.body[-1].value), "<interpreter>", "eval"), globals())
            else:
                exec(compile(tree, "<interpreter>", "exec"), globals())
    except _DSPySubmission as submitted:
        return {"kind": "final", "value": submitted.value}
    except SyntaxError as error:
        return {"kind": "syntax", "error": str(error)}
    except Exception as error:
        return {"kind": "execution_error", "error": type(error).__name__ + ": " + str(error)}
    output = captured.getvalue().rstrip("\n")
    try:
        _dspy_json.dumps(value)
    except (TypeError, ValueError):
        value = repr(value)
    return {"kind": "result", "value": value, "stdout": output}

_dspy_capabilities = set()
_dspy_output_fields = None
'''


class _ToolServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ToolHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        owner: IPythonInterpreter = self.server.owner  # type: ignore[attr-defined]
        try:
            request = json.loads(self.rfile.readline())
            if request.get("token") != owner._token:
                raise PermissionError("invalid host-tool token")
            completed = threading.Event()
            holder: dict[str, Any] = {}
            owner._tool_requests.put((request, completed, holder))
            if not completed.wait(owner._execution_timeout):
                raise TimeoutError("host did not answer tool request")
            response = holder["response"]
        except Exception as exc:
            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        self.wfile.write((json.dumps(response, separators=(",", ":")) + "\n").encode())


class IPythonInterpreter:
    """Trusted local interpreter backed by a persistent IPython kernel process.

    The process boundary improves lifecycle control but is not a security
    sandbox: submitted code retains the user's filesystem, network, environment,
    and subprocess authority.
    """

    def __init__(
        self,
        tools: Mapping[str, Callable[..., Any]] | None = None,
        output_fields: Sequence[Mapping[str, Any]] | None = None,
        *,
        kernel_name: str = "python3",
        startup_timeout: float = 30.0,
        execution_timeout: float = 60.0,
    ) -> None:
        self.tools = dict(tools or {})
        self.output_fields = None if output_fields is None else [dict(field) for field in output_fields]
        self._kernel_name = kernel_name
        self._startup_timeout = startup_timeout
        self._execution_timeout = execution_timeout
        self._manager: Any = None
        self._client: Any = None
        self._server: _ToolServer | None = None
        self._server_thread: threading.Thread | None = None
        self._token = uuid.uuid4().hex
        self._tool_requests: queue.Queue[tuple[dict[str, Any], threading.Event, dict[str, Any]]] = queue.Queue()
        self._ended = False
        self._executing = False

    @property
    def execution_instructions(self) -> str:
        return (
            "Code runs as ordinary CPython in a persistent local IPython kernel subprocess. Variables, imports, "
            "functions, working-directory changes, and installed packages persist for this session. Filesystem, "
            "network, environment, shell, and subprocess access use the host user's permissions. This process "
            "boundary is not a security sandbox."
        )

    def _check_active(self) -> None:
        if self._ended:
            raise CodeInterpreterError("IPythonInterpreter session has been shut down")

    def _terminal(self, message: str, cause: Exception | None = None) -> None:
        self._ended = True
        self._cleanup()
        error = CodeInterpreterError(message)
        if cause is not None:
            raise error from cause
        raise error

    def start(self) -> None:
        self._check_active()
        if self._manager is not None:
            return
        try:
            from jupyter_client import KernelManager

            self._server = _ToolServer(("127.0.0.1", 0), _ToolHandler)
            self._server.owner = self  # type: ignore[attr-defined]
            self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._server_thread.start()

            self._manager = KernelManager(kernel_name=self._kernel_name)
            self._manager.start_kernel(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._client = self._manager.blocking_client()
            self._client.start_channels()
            self._client.wait_for_ready(timeout=self._startup_timeout)
            host, port = self._server.server_address
            bootstrap = (
                f"_dspy_interpreters_host={host!r}\n"
                f"_dspy_interpreters_port={port!r}\n"
                f"_dspy_interpreters_token={self._token!r}\n"
                + _BOOTSTRAP
            )
            reply = self._run_cell(bootstrap, timeout=self._startup_timeout)
            if reply["status"] != "ok":
                self._terminal(f"IPython bootstrap failed: {reply.get('error')}")
        except CodeInterpreterError:
            raise
        except Exception as exc:
            self._terminal(f"Unable to start IPython kernel: {exc}", exc)

    def bind(
        self,
        *,
        tools: Mapping[str, Callable[..., Any]],
        output_fields: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        self._check_active()
        if self._executing:
            raise RuntimeError("Cannot bind tools while IPython execution is active")
        copied_tools = dict(tools)
        for name, tool in copied_tools.items():
            if not isinstance(name, str) or not name.isidentifier() or keyword.iskeyword(name) or name == "SUBMIT":
                raise CodeInterpreterError(f"Invalid tool name: {name!r}")
            if not callable(tool):
                raise CodeInterpreterError(f"Tool {name!r} is not callable")
        copied_fields = None if output_fields is None else [dict(field) for field in output_fields]
        if copied_fields is not None:
            names = [field.get("name") for field in copied_fields]
            if any(not isinstance(name, str) or not name.isidentifier() or keyword.iskeyword(name) for name in names):
                raise CodeInterpreterError("output field names must be Python identifiers")
            if len(names) != len(set(names)):
                raise CodeInterpreterError("output field names must be unique")
        self.tools = copied_tools
        self.output_fields = copied_fields

    def _dispatch_tool_requests(self) -> None:
        while True:
            try:
                request, completed, holder = self._tool_requests.get_nowait()
            except queue.Empty:
                return
            try:
                tool = self.tools[request["name"]]
                value = tool(*request.get("args", []), **request.get("kwargs", {}))
                json.dumps(value)
                response = {"ok": True, "value": value}
            except Exception as exc:
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            holder["response"] = response
            completed.set()

    def _run_cell(self, code: str, *, timeout: float) -> dict[str, Any]:
        message_id = self._client.execute(
            code, silent=False, store_history=False, allow_stdin=False, stop_on_error=True
        )
        value = None
        error = None
        deadline = time.monotonic() + timeout
        while True:
            self._dispatch_tool_requests()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("IPython kernel execution timed out")
            try:
                message = self._client.get_iopub_msg(timeout=min(remaining, 0.05))
            except queue.Empty:
                continue
            if message.get("parent_header", {}).get("msg_id") != message_id:
                continue
            message_type = message["header"]["msg_type"]
            content = message["content"]
            if message_type in {"execute_result", "display_data"}:
                value = content.get("data", {}).get("text/plain")
            elif message_type == "error":
                error = f"{content.get('ename')}: {content.get('evalue')}"
            elif message_type == "status" and content.get("execution_state") == "idle":
                break
        return {"status": "error" if error else "ok", "value": value, "error": error}

    def execute(self, code: str, variables: dict[str, Any] | None = None) -> Any:
        self.start()
        try:
            variables_json = json.dumps(variables or {}, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise CodeInterpreterError(f"IPython variables must be JSON-compatible: {exc}") from exc
        code_b64 = base64.b64encode(code.encode()).decode()
        variables_b64 = base64.b64encode(variables_json.encode()).decode()
        invocation = (
            f"_dspy_execute({code_b64!r}, {variables_b64!r}, {list(self.tools)!r}, "
            f"{self.output_fields!r})"
        )
        self._executing = True
        try:
            reply = self._run_cell(invocation, timeout=self._execution_timeout)
        except TimeoutError as exc:
            try:
                self._manager.interrupt_kernel()
            finally:
                self._terminal("IPython execution timed out; kernel state is no longer trustworthy", exc)
        except Exception as exc:
            self._terminal(f"IPython kernel protocol failed: {exc}", exc)
        finally:
            self._executing = False
        if reply["status"] != "ok" or reply["value"] is None:
            self._terminal(f"IPython execution wrapper failed: {reply.get('error')}")
        try:
            message = ast.literal_eval(reply["value"])
        except (SyntaxError, ValueError) as exc:
            self._terminal(f"IPython returned an invalid execution result: {reply['value']!r}", exc)
        kind = message["kind"]
        if kind == "syntax":
            raise SyntaxError(message["error"])
        if kind == "execution_error":
            raise CodeExecutionError(message["error"])
        if kind == "final":
            return FinalOutput(message["value"])
        return message["value"] if message["value"] is not None else (message["stdout"] or None)

    def _cleanup(self) -> None:
        if self._client is not None:
            try:
                self._client.stop_channels()
            except Exception:
                pass
            self._client = None
        if self._manager is not None:
            try:
                self._manager.shutdown_kernel(now=True)
            except Exception:
                pass
            self._manager = None
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def shutdown(self) -> None:
        if self._ended:
            return
        self._ended = True
        self._cleanup()


IKernelInterpreter = IPythonInterpreter

__all__ = ["IKernelInterpreter", "IPythonInterpreter"]
