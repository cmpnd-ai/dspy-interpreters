from __future__ import annotations

import ast
import contextlib
import dataclasses
import importlib.resources
import inspect
import io
import json
import keyword
import os
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any, NoReturn

from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

from dspy_interpreters.isolation._backend import Backend, LaunchPlan, select_backend, session_paths
from dspy_interpreters.isolation.spec import (
    OWN_ADDRESS_SPACE,
    IsolationReport,
    IsolationSpec,
    IsolationUnsupportedError,
)

_MODES = ("inprocess", "subprocess")
_STDERR_TAIL_BYTES = 64 * 1024
_SHUTDOWN_GRACE_SECONDS = 2.0
_READER_JOIN_SECONDS = 0.2


class _Submission(BaseException):
    def __init__(self, value: Any) -> None:
        self.value = value


class LocalInterpreter:
    """CodeInterpreter that runs on this machine.

    ``mode="inprocess"`` (default) executes generated code inside the DSPy
    process.  It is small and fast and is not a security boundary.

    ``mode="subprocess"`` executes generated code in a separate local worker
    process that speaks the same JSON-lines protocol as ``ModalInterpreter``.
    An :class:`~dspy_interpreters.isolation.IsolationSpec` names the guarantees
    the worker must have; the backend refuses at construction or ``start()``
    when it cannot provide one, and reports what it applied in
    :attr:`isolation_report`.
    """

    def __init__(
        self,
        tools: dict[str, Callable[..., Any]] | None = None,
        output_fields: list[dict[str, Any]] | None = None,
        *,
        mode: str = "inprocess",
        isolation: IsolationSpec | None = None,
        python: str | None = None,
        startup_timeout: float = 30.0,
    ) -> None:
        if mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}, not {mode!r}")
        self.tools = dict(tools or {})
        self.output_fields = None if output_fields is None else [dict(field) for field in output_fields]
        self._mode = mode
        self._namespace: dict[str, Any] = {"__builtins__": __builtins__}
        self._started = False
        self._ended = False
        self._isolation: IsolationSpec | None = None
        self._session: _SubprocessSession | None = None
        if mode == "inprocess":
            if isolation is not None:
                raise IsolationUnsupportedError(
                    {OWN_ADDRESS_SPACE: "in-process mode runs generated code in the host process; use subprocess mode"},
                    backend="inprocess",
                )
            return
        spec = isolation if isolation is not None else IsolationSpec()
        if not isinstance(spec, IsolationSpec):
            raise TypeError("isolation must be an IsolationSpec or None")
        backend = select_backend(spec)
        self._isolation = spec
        self._session = _SubprocessSession(
            spec,
            backend,
            python=python or sys.executable,
            startup_timeout=float(startup_timeout),
        )

    # -- introspection --------------------------------------------------------- #

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def isolation(self) -> IsolationSpec | None:
        return self._isolation

    @property
    def isolation_report(self) -> IsolationReport | None:
        return None if self._session is None else self._session.report

    @property
    def execution_instructions(self) -> str:
        if self._session is not None and self._isolation is not None:
            return (
                "Code runs as CPython in a separate local worker process. State, imports, functions, and variables "
                "persist for this session. Host tools and SUBMIT are available as global functions and execute in "
                f"the host process. Confinement: {self._isolation.describe()}."
            )
        return (
            "Code runs as trusted Python in the host process. State, imports, functions, and variables persist "
            "for this session. Host tools and SUBMIT are available as global functions."
        )

    # -- lifecycle ------------------------------------------------------------- #

    def start(self) -> None:
        if self._session is not None:
            self._session.start()
            self._started = True
            return
        if self._ended:
            raise CodeInterpreterError("interpreter session has been shut down")
        self._started = True

    def bind(
        self,
        *,
        tools: dict[str, Callable[..., Any]],
        output_fields: list[dict[str, Any]] | None = None,
    ) -> None:
        if self._ended or (self._session is not None and self._session.ended):
            raise CodeInterpreterError("interpreter session has been shut down")
        if self._session is not None and self._session.executing:
            raise CodeInterpreterError("Cannot bind while an execution is active")
        invalid_tool = not isinstance(tools, dict) or any(
            not isinstance(name, str) or not callable(tool) for name, tool in tools.items()
        )
        if invalid_tool:
            raise TypeError("tools must map string names to callables")
        if self._session is not None:
            for name in tools:
                if not _valid_tool_name(name):
                    raise TypeError(f"Invalid tool name: {name!r}")
        fields = None if output_fields is None else [dict(field) for field in output_fields]
        if fields is not None:
            names = [field.get("name") for field in fields]
            invalid_name = any(not isinstance(name, str) or not name.isidentifier() for name in names)
            if self._session is not None:
                invalid_name = invalid_name or any(keyword.iskeyword(name) for name in names)
            if invalid_name or len(set(names)) != len(names):
                raise TypeError("output field names must be unique Python identifiers")
        self.tools = dict(tools)
        self.output_fields = fields

    def _submit(self, *args: Any, **kwargs: Any) -> None:
        if self.output_fields is None:
            signature = inspect.Signature([inspect.Parameter("value", inspect.Parameter.POSITIONAL_OR_KEYWORD)])
            value = signature.bind(*args, **kwargs).arguments["value"]
            raise _Submission({"output": value})
        names = [field["name"] for field in self.output_fields]
        signature = inspect.Signature(
            [inspect.Parameter(name, inspect.Parameter.POSITIONAL_OR_KEYWORD) for name in names]
        )
        values = signature.bind(*args, **kwargs).arguments
        raise _Submission(dict(values))

    def execute(self, code: str, variables: dict[str, Any] | None = None) -> Any:
        if self._session is not None:
            return self._session.execute(code, variables, tools=self.tools, output_fields=self.output_fields)
        self.start()
        if variables:
            if any(not isinstance(name, str) or not name.isidentifier() for name in variables):
                raise CodeInterpreterError("variable names must be Python identifiers")
            self._namespace.update(variables)
        # Refresh capabilities on every execution so replacement revokes names.
        old_capabilities = self._namespace.pop("__dspy_capabilities__", set())
        for name in old_capabilities:
            self._namespace.pop(name, None)
        capabilities = set(self.tools) | {"SUBMIT"}
        self._namespace.update(self.tools)
        self._namespace["SUBMIT"] = self._submit
        self._namespace["__dspy_capabilities__"] = capabilities
        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError:
            raise
        stdout = io.StringIO()
        host_dspy_module = sys.modules.get("dspy")
        try:
            with contextlib.redirect_stdout(stdout):
                value = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    prefix = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(compile(prefix, "<interpreter>", "exec"), self._namespace)
                    value = eval(compile(ast.Expression(tree.body[-1].value), "<interpreter>", "eval"), self._namespace)
                else:
                    exec(compile(tree, "<interpreter>", "exec"), self._namespace)
        except _Submission as submission:
            return FinalOutput(submission.value)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CodeExecutionError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            if host_dspy_module is None:
                sys.modules.pop("dspy", None)
            else:
                sys.modules["dspy"] = host_dspy_module
        output = stdout.getvalue().rstrip("\n")
        return value if value is not None else (output or None)

    def shutdown(self) -> None:
        self._ended = True
        if self._session is not None:
            self._session.shutdown()
            return
        self._namespace.clear()


# --------------------------------------------------------------------------- #
# Subprocess mode
# --------------------------------------------------------------------------- #


def _valid_tool_name(name: Any) -> bool:
    return isinstance(name, str) and name.isidentifier() and not keyword.iskeyword(name) and name != "SUBMIT"


def _valid_field_name(name: Any) -> bool:
    return isinstance(name, str) and name.isidentifier() and not keyword.iskeyword(name)


def _check_output_fields(output_fields: list[dict[str, Any]] | None) -> None:
    """Refuse output fields the worker would reject (its check would end the session)."""
    if output_fields is None:
        return
    names = [field.get("name") if isinstance(field, Mapping) else None for field in output_fields]
    if any(not _valid_field_name(name) for name in names) or len(set(names)) != len(names):
        raise CodeInterpreterError("output field names must be unique Python identifiers")


class _RingBuffer:
    """Thread-safe byte ring buffer that keeps the last ``limit`` bytes."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._data = bytearray()
        self._lock = threading.Lock()

    def extend(self, chunk: bytes) -> None:
        with self._lock:
            self._data.extend(chunk)
            if len(self._data) > self._limit:
                del self._data[: len(self._data) - self._limit]

    def text(self) -> str:
        with self._lock:
            return bytes(self._data).decode("utf-8", "replace")


class _SubprocessSession:
    """Owns one worker process and the JSON-lines protocol to it."""

    provider = "Local worker"

    def __init__(self, spec: IsolationSpec, backend: Backend, *, python: str, startup_timeout: float) -> None:
        self.spec = spec
        self.backend = backend
        self.python = python
        self.startup_timeout = startup_timeout
        self.report: IsolationReport | None = None
        self.worker_pid: int | None = None
        self.session_dir: str | None = None
        self.plan: LaunchPlan | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.ended = False
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self._stderr = _RingBuffer(_STDERR_TAIL_BYTES)
        self._stderr_thread: threading.Thread | None = None
        self._stdout_thread: threading.Thread | None = None
        self._execution_lock = threading.Lock()
        self._start_lock = threading.Lock()

    @property
    def executing(self) -> bool:
        return self._execution_lock.locked()

    # -- failure ----------------------------------------------------------- #

    def _check_active(self) -> None:
        if self.ended:
            raise CodeInterpreterError("LocalInterpreter session has been shut down")

    def _fail(self, error: CodeInterpreterError, cause: BaseException | None = None) -> NoReturn:
        """Kill the worker, mark the session ended, and raise ``error``."""
        self.ended = True
        self._destroy()
        if cause is not None:
            raise error from cause
        raise error

    def _terminal(self, message: str, cause: BaseException | None = None) -> NoReturn:
        self.ended = True
        self._destroy()
        thread = self._stderr_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=0.5)  # let the drainer collect the worker's last words
        tail = self._stderr.text().strip()
        if tail:
            message = f"{message}; worker stderr: {tail}"
        self._fail(CodeInterpreterError(message), cause)

    # -- process ----------------------------------------------------------- #

    def _destroy(self) -> None:
        process = self.process
        if process is not None:
            if self.plan is not None:
                try:
                    self.backend.kill(process, self.plan)
                except Exception:
                    pass
            try:
                process.kill()
            except Exception:
                pass
            try:
                process.wait(timeout=_SHUTDOWN_GRACE_SECONDS)
            except Exception:
                pass
            with contextlib.suppress(Exception):
                if process.stdin is not None:
                    process.stdin.close()
            # stdout/stderr belong to their reader threads, which close them on EOF.  Closing a
            # BufferedReader from here blocks on its buffer lock while a reader is inside a raw
            # read, and a guest process that escaped the process group can hold the pipe open
            # for as long as it lives.  Leaking one pipe fd until then is acceptable; hanging is not.
            for thread, stream in ((self._stdout_thread, process.stdout), (self._stderr_thread, process.stderr)):
                if thread is not None and thread is not threading.current_thread():
                    thread.join(timeout=_READER_JOIN_SECONDS)
                if stream is not None and (thread is None or not thread.is_alive()):
                    with contextlib.suppress(Exception):
                        stream.close()
        self.process = None
        self._remove_session_dir()

    def _remove_session_dir(self) -> None:
        session_dir = self.session_dir
        self.session_dir = None
        if session_dir is None:
            return
        try:
            for root, dirs, files in os.walk(session_dir):
                for name in dirs:
                    with contextlib.suppress(OSError):
                        os.chmod(os.path.join(root, name), stat.S_IRWXU)
                for name in files:
                    with contextlib.suppress(OSError):
                        os.chmod(os.path.join(root, name), stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        shutil.rmtree(session_dir, ignore_errors=True)

    def _spawn(self, plan: LaunchPlan) -> subprocess.Popen[bytes]:
        """Spawn the worker from a thread that lives exactly as long as the worker.

        On Linux ``PR_SET_PDEATHSIG`` fires when the *thread* that spawned the
        child exits, so the child must not be spawned from a short-lived caller
        thread, and the spawning thread must not end for any other reason than
        the worker's own exit (it blocks in ``process.wait()``).  stderr is
        drained by a separate daemon thread that owns the stream.
        """
        outcome: dict[str, Any] = {}
        spawned = threading.Event()

        def supervise() -> None:
            try:
                process = subprocess.Popen(
                    plan.argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=plan.env,
                    cwd=plan.cwd,
                    **plan.popen_kwargs,
                )
            except BaseException as exc:
                outcome["error"] = exc
                spawned.set()
                return
            outcome["process"] = process
            spawned.set()
            with contextlib.suppress(Exception):
                process.wait()

        def drain(stderr: Any) -> None:
            try:
                for chunk in iter(lambda: stderr.read1(4096), b""):
                    self._stderr.extend(chunk)
            except Exception:
                pass
            finally:
                with contextlib.suppress(Exception):
                    stderr.close()

        thread = threading.Thread(target=supervise, name="dspy-local-worker", daemon=True)
        thread.start()
        spawned.wait()
        if "error" in outcome:
            raise outcome["error"]
        process = outcome["process"]
        if process.stderr is not None:
            drainer = threading.Thread(target=drain, args=(process.stderr,), name="dspy-local-stderr", daemon=True)
            drainer.start()
            self._stderr_thread = drainer
        return process

    def _pump_stdout(self, stream: Any) -> None:
        try:
            for line in iter(stream.readline, b""):
                self._lines.put(line)
        except Exception:
            pass
        finally:
            self._lines.put(None)
            with contextlib.suppress(Exception):
                stream.close()

    def _launch(self) -> None:
        session_dir = tempfile.mkdtemp(prefix="dspy-interp-")
        self.session_dir = session_dir
        paths = session_paths(session_dir)
        for path in paths.values():
            os.mkdir(path, stat.S_IRWXU)
        worker_path = os.path.join(paths["bootstrap"], "worker.py")
        source = importlib.resources.files("dspy_interpreters.isolation").joinpath("_worker.py").read_text("utf-8")
        with open(worker_path, "w", encoding="utf-8") as handle:
            handle.write(source)
        os.chmod(worker_path, stat.S_IRUSR)
        os.chmod(paths["bootstrap"], stat.S_IRUSR | stat.S_IXUSR)

        plan = self.backend.plan(self.spec, python=self.python, worker_path=worker_path, session_dir=session_dir)
        self.plan = plan
        process = self._spawn(plan)
        self.process = process
        reader = threading.Thread(target=self._pump_stdout, args=(process.stdout,), name="dspy-local-stdout")
        reader.daemon = True
        self._stdout_thread = reader
        reader.start()
        self.backend.attach(process, plan)

        self._send({"type": "policy", **plan.policy})
        deadline = time.monotonic() + self.startup_timeout
        ready = self._receive(deadline, f"{self.provider} did not become ready within {self.startup_timeout:g}s")
        if ready.get("type") == "terminal_error":
            self._terminal(f"{self.provider} failed during startup: {ready.get('error')}")
        applied = ready.get("applied")
        skipped = ready.get("skipped")
        if ready.get("type") != "ready" or not isinstance(applied, list) or not isinstance(skipped, dict):
            self._terminal(f"{self.provider} returned an invalid ready message: {ready!r}")
        self.worker_pid = ready.get("pid") if isinstance(ready.get("pid"), int) else process.pid

        unmet: dict[str, str] = {}
        for name in plan.required_applied:
            if not any(item == name or item.startswith(name + ":") for item in applied):
                unmet[name] = str(skipped.get(name, "not reported as applied by the worker"))
        if unmet:
            self._fail(IsolationUnsupportedError(unmet, backend=self.backend.name))
        notes = list(plan.report.notes)
        for name, reason in skipped.items():
            if name not in plan.required_applied:
                notes.append(f"optional policy item {name!r} not applied: {reason}")
        self.report = dataclasses.replace(plan.report, notes=tuple(notes))

    def start(self) -> None:
        self._check_active()
        with self._start_lock:
            self._check_active()
            if self.process is not None:
                return
            try:
                self._launch()
            except CodeInterpreterError:
                if not self.ended:
                    self.ended = True
                    self._destroy()
                raise
            except Exception as exc:
                self._terminal(f"Unable to start {self.provider}: {exc}", exc)

    # -- protocol ---------------------------------------------------------- #

    def _write(self, message: dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None:
            raise BrokenPipeError("worker process is not running")
        process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
        process.stdin.flush()

    def _send(self, message: dict[str, Any]) -> None:
        try:
            self._write(message)
        except Exception as exc:
            self._terminal(f"{self.provider} stdin protocol failed: {exc}", exc)

    def _receive(self, deadline: float | None, timeout_message: str) -> dict[str, Any]:
        while True:
            timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                line = self._lines.get(timeout=timeout)
            except queue.Empty:
                self._terminal(timeout_message)
            if line is None:
                self._terminal(f"{self.provider} exited unexpectedly{self._exit_status()}")
            try:
                message = json.loads(line.decode("utf-8"))
            except Exception as exc:
                self._terminal(f"{self.provider} stdout protocol failed: {exc}", exc)
            if not isinstance(message, dict):
                self._terminal(f"{self.provider} returned a non-object message: {message!r}")
            return message

    def _exit_status(self) -> str:
        process = self.process
        if process is None:
            return ""
        try:
            code = process.wait(timeout=1.0)
        except Exception:
            return ""
        return f" (exit code {code})"

    def _handle_tool(self, request: dict[str, Any], tools: Mapping[str, Callable[..., Any]]) -> None:
        try:
            tool = tools[request["name"]]
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

    # -- execute ----------------------------------------------------------- #

    def execute(
        self,
        code: str,
        variables: dict[str, Any] | None,
        *,
        tools: Mapping[str, Callable[..., Any]],
        output_fields: list[dict[str, Any]] | None,
    ) -> Any:
        if not self._execution_lock.acquire(blocking=False):
            raise CodeInterpreterError(f"{self.provider} already has an active execution")
        try:
            self.start()
            variables = dict(variables or {})
            if any(not isinstance(name, str) or not name.isidentifier() for name in variables):
                raise CodeInterpreterError("variable names must be Python identifiers")
            try:
                json.dumps(variables, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise CodeInterpreterError(f"{self.provider} variables must be JSON-compatible: {exc}") from exc
            tool_names = list(tools)
            for name in tool_names:
                if not _valid_tool_name(name):
                    raise CodeInterpreterError(f"Invalid tool name: {name!r}")
            _check_output_fields(output_fields)
            wall_time = self.spec.limits.wall_time_seconds
            deadline = None if wall_time is None else time.monotonic() + wall_time
            timeout_message = (
                f"{self.provider} exceeded wall time of {wall_time or 0:g}s; "
                "the worker was killed and its state is lost"
            )
            settled = False
            try:
                self._send(
                    {
                        "type": "execute",
                        "code": code,
                        "variables": variables,
                        "tools": tool_names,
                        "output_fields": output_fields,
                    }
                )
                while True:
                    message = self._receive(deadline, timeout_message)
                    if message.get("type") == "tool_request":
                        # Host tool time does not count against the worker's wall-time budget.
                        started = time.monotonic()
                        self._handle_tool(message, tools)
                        if deadline is not None:
                            deadline += time.monotonic() - started
                        continue
                    if message.get("type") == "terminal_error":
                        self._terminal(f"{self.provider} failed: {message.get('error')}")
                    if message.get("type") != "execution_result":
                        self._terminal(f"{self.provider} returned an unknown message: {message!r}")
                    break
                settled = True
            finally:
                if not settled and not self.ended:
                    # The request is in flight and no result was consumed (KeyboardInterrupt while
                    # waiting, a host tool that raised a BaseException, ...): every later reply would
                    # be off by one, so the session is unusable.  Kill the worker.
                    self.ended = True
                    self._destroy()
            kind = message.get("kind")
            if kind == "syntax" and isinstance(message.get("error"), str):
                raise SyntaxError(message["error"])
            if kind == "execution_error" and isinstance(message.get("error"), str):
                raise CodeExecutionError(message["error"])
            if kind == "final" and "value" in message:
                return FinalOutput(message["value"])
            if kind != "result" or "value" not in message or "stdout" not in message:
                self._terminal(f"{self.provider} returned a malformed execution result: {message!r}")
            return message["value"] if message["value"] is not None else (message["stdout"] or None)
        finally:
            self._execution_lock.release()

    # -- shutdown ---------------------------------------------------------- #

    def shutdown(self) -> None:
        if self.ended:
            self._remove_session_dir()
            return
        self.ended = True
        process = self.process
        if process is not None:
            try:
                self._write({"type": "shutdown"})
            except Exception:
                pass
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except Exception:
                pass
            try:
                process.wait(timeout=_SHUTDOWN_GRACE_SECONDS)
            except Exception:
                pass
        self._destroy()


__all__ = ["LocalInterpreter"]
