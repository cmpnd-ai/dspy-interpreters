from __future__ import annotations

import json
import keyword
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

_WORKER = r"""
import ast
import contextlib
import io
import json
import sys
import uuid

namespace = {"__builtins__": __builtins__}
capabilities = set()
output_fields = None

class Submission(BaseException):
    def __init__(self, value):
        self.value = value

class HostToolError(RuntimeError):
    pass

def send(message):
    sys.__stdout__.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.__stdout__.flush()

def receive():
    line = sys.__stdin__.readline()
    if not line:
        raise EOFError("host closed the Modal interpreter protocol")
    return json.loads(line)

def call_tool(name, *args, **kwargs):
    request_id = uuid.uuid4().hex
    send({"type": "tool_request", "id": request_id, "name": name, "args": args, "kwargs": kwargs})
    response = receive()
    if response.get("type") != "tool_response" or response.get("id") != request_id:
        raise RuntimeError("mismatched host-tool response")
    if not response["ok"]:
        raise HostToolError(response["error"])
    return response["value"]

def bind(tool_names, fields):
    global capabilities, output_fields
    for old_name in capabilities:
        namespace.pop(old_name, None)
    capabilities = set(tool_names)
    output_fields = fields
    for tool_name in tool_names:
        def tool(*args, __name=tool_name, **kwargs):
            return call_tool(__name, *args, **kwargs)
        tool.__name__ = tool_name
        namespace[tool_name] = tool

    def submit(*args, **kwargs):
        if output_fields is None:
            if len(args) != 1 or kwargs:
                raise TypeError("SUBMIT requires one output value")
            value = {"output": args[0]}
        else:
            names = [field["name"] for field in output_fields]
            if args and kwargs:
                raise TypeError("SUBMIT accepts positional or keyword values, not both")
            value = dict(zip(names, args)) if args else dict(kwargs)
            if set(value) != set(names):
                raise TypeError("SUBMIT fields do not match the configured output fields")
        raise Submission(value)
    namespace["SUBMIT"] = submit

def execute(request):
    bind(request["tools"], request["output_fields"])
    namespace.update(request["variables"])
    captured = io.StringIO()
    try:
        tree = ast.parse(request["code"], mode="exec")
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            value = None
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                prefix = ast.Module(body=tree.body[:-1], type_ignores=[])
                exec(compile(prefix, "<interpreter>", "exec"), namespace)
                value = eval(compile(ast.Expression(tree.body[-1].value), "<interpreter>", "eval"), namespace)
            else:
                exec(compile(tree, "<interpreter>", "exec"), namespace)
    except Submission as submitted:
        return {"type": "execution_result", "kind": "final", "value": submitted.value}
    except SyntaxError as error:
        return {"type": "execution_result", "kind": "syntax", "error": str(error)}
    except Exception as error:
        return {
            "type": "execution_result",
            "kind": "execution_error",
            "error": type(error).__name__ + ": " + str(error),
        }
    output = captured.getvalue().rstrip("\n")
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        value = repr(value)
    return {"type": "execution_result", "kind": "result", "value": value, "stdout": output}

send({"type": "ready"})
while True:
    try:
        request = receive()
        if request.get("type") == "shutdown":
            break
        if request.get("type") != "execute":
            raise ValueError("unknown host protocol message")
        send(execute(request))
    except EOFError:
        break
    except Exception as error:
        send({"type": "terminal_error", "error": type(error).__name__ + ": " + str(error)})
        break
"""


class ModalInterpreter:
    """Persistent remote Python interpreter backed by a Modal Sandbox.

    Host tools use framed JSON lines over the sandbox process's stdin/stdout.
    The guest blocks while the callable executes on the host, so provider
    credentials and callable implementations never need to enter the sandbox.
    """

    _provider_name = "Modal"

    def __init__(
        self,
        tools: Mapping[str, Callable[..., Any]] | None = None,
        output_fields: Sequence[Mapping[str, Any]] | None = None,
        *,
        app_name: str = "dspy-interpreters",
        timeout: int = 3600,
        idle_timeout: int = 600,
        cpu: float = 1.0,
        memory: int = 1024,
        block_network: bool = True,
        sandbox_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.tools = dict(tools or {})
        self.output_fields = None if output_fields is None else [dict(field) for field in output_fields]
        self._app_name = app_name
        self._timeout = timeout
        self._idle_timeout = idle_timeout
        self._cpu = cpu
        self._memory = memory
        self._block_network = block_network
        self._sandbox_factory = sandbox_factory
        self._sandbox: Any = None
        self._stdout: Any = None
        self._ended = False
        self._execution_lock = threading.Lock()
        self._start_lock = threading.Lock()

    @property
    def execution_instructions(self) -> str:
        network = "disabled" if self._block_network else "enabled by explicit host configuration"
        return (
            "Code runs as CPython in a persistent remote Modal Sandbox. State and installed packages persist for "
            f"this session. Network access is {network}. Host tools are synchronous capabilities whose code and "
            "credentials remain in the host process."
        )

    def _check_active(self) -> None:
        if self._ended:
            raise CodeInterpreterError(f"{type(self).__name__} session has been shut down")

    def _send(self, message: dict[str, Any]) -> None:
        try:
            self._sandbox.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            self._sandbox.stdin.drain()
        except Exception as exc:
            self._terminal(f"{self._provider_name} stdin protocol failed: {exc}", exc)

    def _receive(self) -> dict[str, Any]:
        try:
            line = next(self._stdout)
            message = json.loads(line)
        except Exception as exc:
            self._terminal(f"{self._provider_name} stdout protocol failed: {exc}", exc)
        if not isinstance(message, dict):
            self._terminal(f"{self._provider_name} worker returned a non-object message: {message!r}")
        return message

    def _terminal(self, message: str, cause: Exception | None = None) -> None:
        self._ended = True
        if self._sandbox is not None:
            try:
                self._sandbox.terminate(wait=True)
            except Exception:
                pass
            finally:
                self._sandbox = None
                self._stdout = None
        error = CodeInterpreterError(message)
        if cause is not None:
            raise error from cause
        raise error

    def start(self) -> None:
        self._check_active()
        with self._start_lock:
            self._check_active()
            if self._sandbox is not None:
                return
            try:
                if self._sandbox_factory is not None:
                    self._sandbox = self._sandbox_factory()
                else:
                    import modal

                    app = modal.App.lookup(self._app_name, create_if_missing=True)
                    self._sandbox = modal.Sandbox.create(
                        "python",
                        "-u",
                        "-c",
                        _WORKER,
                        app=app,
                        image=modal.Image.debian_slim(),
                        timeout=self._timeout,
                        idle_timeout=self._idle_timeout,
                        cpu=self._cpu,
                        memory=self._memory,
                        block_network=self._block_network,
                        verbose=False,
                    )
                self._stdout = iter(self._sandbox.stdout)
                ready = self._receive()
            except CodeInterpreterError:
                raise
            except Exception as exc:
                self._terminal(f"Unable to start {self._provider_name} sandbox: {exc}", exc)
            if ready != {"type": "ready"}:
                self._terminal(f"{self._provider_name} worker returned an invalid ready message: {ready!r}")

    def bind(
        self,
        *,
        tools: Mapping[str, Callable[..., Any]],
        output_fields: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        self._check_active()
        if self._execution_lock.locked():
            raise CodeInterpreterError(f"Cannot bind while {self._provider_name} execution is active")
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

    def _handle_tool(self, request: dict[str, Any]) -> None:
        try:
            tool = self.tools[request["name"]]
            value = tool(*request.get("args", []), **request.get("kwargs", {}))
            json.dumps(value)
            response = {"type": "tool_response", "id": request["id"], "ok": True, "value": value}
        except Exception as exc:
            response = {
                "type": "tool_response",
                "id": request.get("id"),
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        self._send(response)

    def execute(self, code: str, variables: dict[str, Any] | None = None) -> Any:
        if not self._execution_lock.acquire(blocking=False):
            raise CodeInterpreterError(f"{self._provider_name} already has an active execution")
        set_deadline = getattr(self._stdout, "set_deadline", None)
        clear_deadline = getattr(self._stdout, "clear_deadline", None)
        try:
            self.start()
            set_deadline = getattr(self._stdout, "set_deadline", None)
            clear_deadline = getattr(self._stdout, "clear_deadline", None)
            if callable(set_deadline):
                set_deadline()
            try:
                json.dumps(variables or {}, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise CodeInterpreterError(f"{self._provider_name} variables must be JSON-compatible: {exc}") from exc
            self._send(
                {
                    "type": "execute",
                    "code": code,
                    "variables": variables or {},
                    "tools": list(self.tools),
                    "output_fields": self.output_fields,
                }
            )
            while True:
                message = self._receive()
                if message.get("type") == "tool_request":
                    self._handle_tool(message)
                    continue
                if message.get("type") == "terminal_error":
                    self._terminal(f"{self._provider_name} worker failed: {message.get('error')}")
                if message.get("type") != "execution_result":
                    self._terminal(f"{self._provider_name} worker returned an unknown message: {message!r}")
                break
            kind = message.get("kind")
            if kind == "syntax" and isinstance(message.get("error"), str):
                raise SyntaxError(message["error"])
            if kind == "execution_error" and isinstance(message.get("error"), str):
                raise CodeExecutionError(message["error"])
            if kind == "final" and "value" in message:
                return FinalOutput(message["value"])
            if kind != "result" or "value" not in message or "stdout" not in message:
                self._terminal(f"{self._provider_name} worker returned a malformed execution result: {message!r}")
            return message["value"] if message["value"] is not None else (message["stdout"] or None)
        finally:
            if callable(clear_deadline):
                clear_deadline()
            self._execution_lock.release()

    def shutdown(self) -> None:
        if self._ended:
            return
        self._ended = True
        if self._sandbox is not None:
            try:
                self._send({"type": "shutdown"})
            except CodeInterpreterError:
                pass
            try:
                self._sandbox.terminate(wait=True)
            finally:
                self._sandbox = None


__all__ = ["ModalInterpreter"]
