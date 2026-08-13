from __future__ import annotations

import subprocess
import sys
import threading
from typing import Any

import pytest
from dspy import CodeInterpreterError

from dspy_interpreters import check_flex_facade, check_interpreter, check_rlm
from dspy_interpreters.modal import _WORKER, ModalInterpreter


class _Input:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, value: str) -> None:
        self._stream.write(value)

    def drain(self) -> None:
        self._stream.flush()


class _ProcessSandbox:
    """Modal stream-contract double backed by an isolated local process."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-u", "-c", _WORKER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.stdin = _Input(self.process.stdin)
        self.stdout = self.process.stdout

    def terminate(self, wait: bool = False) -> int | None:
        if self.process.poll() is None:
            self.process.terminate()
        return self.process.wait(timeout=5) if wait else None


class _FakeInput:
    def write(self, value: str) -> None:
        pass

    def drain(self) -> None:
        pass


class _MessageSandbox:
    def __init__(self, message: str) -> None:
        self.stdin = _FakeInput()
        self.stdout = iter(['{"type":"ready"}\n', message + "\n"])
        self.terminated = False

    def terminate(self, wait: bool = False) -> None:
        self.terminated = True


def _factory() -> ModalInterpreter:
    return ModalInterpreter(sandbox_factory=_ProcessSandbox)


def test_modal_protocol_against_process_double():
    assert check_interpreter(_factory).passed
    assert check_rlm(_factory).passed
    assert check_flex_facade(_factory).passed


def test_modal_rejects_nan_variables():
    interpreter = _factory()
    try:
        with pytest.raises(CodeInterpreterError, match="JSON-compatible"):
            interpreter.execute("value", {"value": float("nan")})
    finally:
        interpreter.shutdown()


def test_modal_rejects_reentrant_execution_without_deadlock():
    interpreter = _factory()

    def nested():
        return interpreter.execute("40 + 2")

    interpreter.bind(tools={"nested": nested})
    try:
        with pytest.raises(Exception, match="already has an active execution"):
            interpreter.execute("nested()")
    finally:
        interpreter.shutdown()


def test_modal_rejects_concurrent_execution_without_corrupting_stream():
    entered = threading.Event()
    release = threading.Event()

    def wait():
        entered.set()
        release.wait(timeout=2)

    interpreter = _factory()
    interpreter.bind(tools={"wait": wait})
    thread = threading.Thread(target=lambda: interpreter.execute("wait()"))
    thread.start()
    assert entered.wait(timeout=2)
    try:
        with pytest.raises(CodeInterpreterError, match="already has an active execution"):
            interpreter.execute("40 + 2")
    finally:
        release.set()
        thread.join(timeout=2)
        interpreter.shutdown()
    assert not thread.is_alive()


@pytest.mark.parametrize("message", ["[]", '{"type":"execution_result"}', '{"type":"execution_result","kind":"wat"}'])
def test_modal_terminalizes_malformed_worker_results(message):
    sandbox = _MessageSandbox(message)
    interpreter = ModalInterpreter(sandbox_factory=lambda: sandbox)
    with pytest.raises(CodeInterpreterError, match="worker returned"):
        interpreter.execute("40 + 2")
    assert sandbox.terminated
    assert interpreter._ended
    assert interpreter._sandbox is None
