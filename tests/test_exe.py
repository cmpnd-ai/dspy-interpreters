from __future__ import annotations

import subprocess
import sys
from typing import Any

from dspy_interpreters import (
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)
from dspy_interpreters.exe import ExeDevInterpreter, _find_field
from dspy_interpreters.modal import _WORKER


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


def test_exe_protocol_against_process_double():
    assert check_interpreter(_factory).passed
    assert check_bind(_factory).passed
    assert check_execution_instructions(_factory).passed
    assert check_rlm(_factory).passed
    assert check_flex_facade(_factory).passed


def test_exe_finds_documented_nested_lifecycle_fields():
    response = {"vms": [{"vm_name": "test-vm", "ssh_dest": "vm+test-vm@exe.dev"}]}
    assert _find_field(response, "vm_name") == "test-vm"
    assert _find_field(response, "ssh_dest") == "vm+test-vm@exe.dev"
