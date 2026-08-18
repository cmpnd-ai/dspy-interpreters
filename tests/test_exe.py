from __future__ import annotations

import subprocess
import sys
import time
from typing import Any

import pytest
from dspy import CodeInterpreterError

from dspy_interpreters import (
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)
from dspy_interpreters.exe import ExeDevInterpreter, _find_field, _TimedLines, _vm_name_from_ssh_dest
from dspy_interpreters.modal import _WORKER, ModalInterpreter


class _Input:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, value: str) -> None:
        self._stream.write(value)

    def drain(self) -> None:
        self._stream.flush()


class _ProcessSandbox:
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


def _factory() -> ExeDevInterpreter:
    return ExeDevInterpreter(process_factory=_ProcessSandbox, owns_vm=False)


_factory.execution_instructions = ExeDevInterpreter.execution_instructions  # type: ignore[attr-defined]


def test_exe_protocol_against_process_double():
    assert check_interpreter(_factory).passed
    assert check_execution_instructions(_factory).passed
    assert check_rlm(_factory).passed
    assert check_flex_facade(_factory).passed


def test_exe_finds_documented_nested_lifecycle_fields():
    response = {"vms": [{"vm_name": "test-vm", "ssh_dest": "vm+test-vm@exe.dev"}]}
    assert _find_field(response, "vm_name") == "test-vm"
    assert _find_field(response, "ssh_dest") == "vm+test-vm@exe.dev"


def test_exe_derives_cleanup_name_from_documented_destinations():
    assert _vm_name_from_ssh_dest("vm+test-vm@exe.dev") == "test-vm"
    assert _vm_name_from_ssh_dest("test-vm.exe.xyz") == "test-vm"
    interpreter = ExeDevInterpreter(ssh_dest="vm+test-vm@exe.dev", owns_vm=True)
    assert interpreter._vm_name == "test-vm"


def test_exe_control_quotes_remote_arguments(monkeypatch):
    command = None

    def run(args, **kwargs):
        nonlocal command
        command = args
        return subprocess.CompletedProcess(args, 0, "{}", "")

    monkeypatch.setattr(subprocess, "run", run)
    interpreter = ExeDevInterpreter(process_factory=_ProcessSandbox, owns_vm=False)
    interpreter._control("new", "--name", "name with spaces; echo nope")
    assert command[-1] == "new --name 'name with spaces; echo nope' --json"
    assert command[-2] == "exe.dev"


def test_exe_shutdown_removes_owned_vm_after_transport_failure(monkeypatch):
    removed = []
    interpreter = ExeDevInterpreter(ssh_dest="vm+test-vm@exe.dev", vm_name="test-vm", owns_vm=True)
    monkeypatch.setattr(ModalInterpreter, "shutdown", lambda self: (_ for _ in ()).throw(RuntimeError("failed")))
    monkeypatch.setattr(interpreter, "_control", lambda *args: removed.append(args))

    with pytest.raises(RuntimeError, match="failed"):
        interpreter.shutdown()

    assert removed == [("rm", "test-vm")]


def test_exe_output_read_has_deadline():
    class Stream:
        def __iter__(self):
            time.sleep(0.1)
            return iter(())

    lines = _TimedLines(Stream(), timeout=0.01)
    with pytest.raises(TimeoutError, match="execution exceeded"):
        next(lines)


def test_exe_rejects_invalid_provider_destination():
    with pytest.raises(CodeInterpreterError, match="invalid ssh_dest"):
        ExeDevInterpreter(ssh_dest="-oProxyCommand=bad", owns_vm=False)

    interpreter = ExeDevInterpreter(process_factory=_ProcessSandbox, owns_vm=False)
    interpreter._control = lambda *args: {"ssh_dest": "-oProxyCommand=bad", "vm_name": "test-vm"}
    with pytest.raises(CodeInterpreterError, match="invalid ssh_dest"):
        interpreter._provision()
