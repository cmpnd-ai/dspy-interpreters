from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput


class SubprocessInterpreter:
    """Persistent CPython worker with a JSON-only process boundary.

    This separates generated code from DSPy's memory, stdout, and lifecycle,
    but it is not a security sandbox. The worker retains the host user's files,
    environment, credentials, subprocess, and network authority.
    """

    execution_instructions = (
        "Code runs as Python in a persistent local subprocess. State, imports, functions, and JSON-compatible "
        "variables persist for this session. Host tools and SUBMIT are available as global functions."
    )

    def __init__(
        self,
        tools: dict[str, Callable[..., Any]] | None = None,
        output_fields: list[dict[str, Any]] | None = None,
        *,
        execution_timeout: float | None = None,
        python: str | None = None,
    ) -> None:
        if execution_timeout is not None and execution_timeout <= 0:
            raise ValueError("execution_timeout must be positive or None")
        self.tools = dict(tools or {})
        self.output_fields = None if output_fields is None else [dict(field) for field in output_fields]
        self.execution_timeout = execution_timeout
        self.python = python or sys.executable
        self._process: subprocess.Popen[str] | None = None
        self._responses: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._ended = False

    def start(self) -> None:
        if self._ended:
            raise CodeInterpreterError("interpreter session has been shut down")
        if self._process is not None:
            return
        try:
            worker = Path(__file__).with_name("_subprocess_worker.py")
            process = subprocess.Popen(
                [self.python, "-I", "-u", str(worker)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise CodeInterpreterError(f"Unable to start Python worker: {exc}") from exc
        self._process = process
        threading.Thread(target=self._read_responses, args=(process,), daemon=True).start()
        message = self._receive("Python worker did not start", timeout=10)
        if message.get("type") != "ready":
            self._terminal(f"Python worker returned an invalid startup message: {message!r}")

    def _read_responses(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            self._responses.put(line)
        self._responses.put(None)

    def _send(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            self._terminal("Python worker is not running")
        try:
            process.stdin.write(json.dumps(message, separators=(",", ":"), allow_nan=False) + "\n")
            process.stdin.flush()
        except (OSError, TypeError, ValueError) as exc:
            self._terminal(f"Unable to send request to Python worker: {exc}", exc)

    def _receive(self, timeout_message: str, *, timeout: float | None) -> dict[str, Any]:
        try:
            line = self._responses.get(timeout=timeout)
        except queue.Empty:
            self._terminal(timeout_message)
        if line is None:
            self._terminal("Python worker exited unexpectedly")
        try:
            message = json.loads(line)
        except (TypeError, json.JSONDecodeError) as exc:
            self._terminal(f"Python worker returned invalid JSON: {line!r}", exc)
        if not isinstance(message, dict):
            self._terminal(f"Python worker returned a non-object message: {message!r}")
        return message

    def _terminal(self, message: str, cause: BaseException | None = None) -> NoReturn:
        self._ended = True
        self._kill()
        error = CodeInterpreterError(message)
        if cause is None:
            raise error
        raise error from cause

    def _kill(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()

    def _handle_tool(self, request: dict[str, Any]) -> None:
        try:
            tool = self.tools[request["name"]]
            value = tool(*request.get("args", []), **request.get("kwargs", {}))
            json.dumps(value, allow_nan=False)
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
        if not self._lock.acquire(blocking=False):
            raise CodeInterpreterError("interpreter already has an active execution")
        try:
            variables = {} if variables is None else variables
            if not isinstance(code, str):
                raise CodeInterpreterError("code must be a string")
            if not isinstance(variables, dict) or any(
                not isinstance(name, str) or not name.isidentifier() for name in variables
            ):
                raise CodeInterpreterError("variables must map Python identifiers to JSON-compatible values")
            try:
                json.dumps(variables, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise CodeInterpreterError(f"variables must be JSON-compatible: {exc}") from exc
            self.start()
            deadline = None if self.execution_timeout is None else time.monotonic() + self.execution_timeout
            self._send(
                {
                    "type": "execute",
                    "code": code,
                    "variables": variables,
                    "tools": list(self.tools),
                    "output_fields": self.output_fields,
                }
            )
            while True:
                timeout = None if deadline is None else max(0, deadline - time.monotonic())
                timeout_message = (
                    "Python worker did not respond"
                    if self.execution_timeout is None
                    else f"Python worker exceeded execution timeout of {self.execution_timeout:g}s"
                )
                message = self._receive(timeout_message, timeout=timeout)
                kind = message.get("type")
                if kind == "tool_request":
                    self._handle_tool(message)
                    continue
                if kind == "terminal_error":
                    self._terminal(f"Python worker failed: {message.get('error')}")
                if kind != "execution_result":
                    self._terminal(f"Python worker returned an unknown message: {message!r}")
                result_kind = message.get("kind")
                if result_kind == "syntax":
                    raise SyntaxError(message.get("error"))
                if result_kind == "execution_error":
                    raise CodeExecutionError(message.get("error"))
                if result_kind == "final":
                    return FinalOutput(message.get("value"))
                if result_kind != "result":
                    self._terminal(f"Python worker returned an unknown result: {message!r}")
                value = message.get("value")
                return value if value is not None else (message.get("stdout") or None)
        finally:
            self._lock.release()

    def shutdown(self) -> None:
        if self._ended:
            return
        self._ended = True
        if self._process is not None:
            try:
                self._send({"type": "shutdown"})
                self._process.wait(timeout=1)
            except (CodeInterpreterError, subprocess.TimeoutExpired):
                pass
        self._kill()
