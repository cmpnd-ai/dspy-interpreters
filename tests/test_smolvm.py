from __future__ import annotations

import subprocess
import sys

import pytest
from dspy import CodeInterpreterError

from dspy_interpreters import check_execution_instructions, check_flex_facade, check_interpreter, check_rlm
from dspy_interpreters import smolvm as smolvm_module
from dspy_interpreters.modal import _WORKER
from dspy_interpreters.smolvm import SmolvmInterpreter, _WorkerProcess


def _local_worker() -> _WorkerProcess:
    return _WorkerProcess([sys.executable, "-u", "-c", _WORKER], execution_timeout=30)


def _factory() -> SmolvmInterpreter:
    return SmolvmInterpreter(process_factory=_local_worker)


_factory.execution_instructions = SmolvmInterpreter.execution_instructions  # type: ignore[attr-defined]


def test_smolvm_protocol_against_local_worker():
    assert check_interpreter(_factory).passed
    assert check_execution_instructions(_factory).passed
    assert check_rlm(_factory).passed
    assert check_flex_facade(_factory).passed


def test_smolvm_session_owns_one_machine_without_network(monkeypatch):
    commands = []
    workers = []

    def run(args, **kwargs):
        commands.append(args[1:])
        return subprocess.CompletedProcess(args, 0, "", "")

    def worker(command, execution_timeout):
        workers.append(command[:-1])
        return _local_worker()

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(smolvm_module, "_WorkerProcess", worker)
    interpreter = SmolvmInterpreter(pack="dspy.smolmachine")
    name = interpreter._machine
    try:
        assert interpreter.execute("6 * 7") == 42
    finally:
        interpreter.shutdown()

    assert commands == [
        ["machine", "create", "--name", name, "--from", "dspy.smolmachine", "--cpus", "1", "--mem", "1024"],
        ["machine", "start", "--name", name],
        ["machine", "delete", "--name", name, "--force"],
    ]
    assert workers == [["smolvm", "machine", "exec", "--name", name, "-i", "--", "python3", "-u", "-c"]]


def test_smolvm_missing_cli_is_a_clear_error():
    interpreter = SmolvmInterpreter(smolvm="/nonexistent/smolvm")
    with pytest.raises(CodeInterpreterError, match="smolvm CLI not found"):
        interpreter.start()


def test_smolvm_failed_boot_deletes_the_machine(monkeypatch):
    commands = []

    def run(args, **kwargs):
        commands.append(args[1:3])
        return subprocess.CompletedProcess(args, 1 if args[2] == "start" else 0, "", "boot failed")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(CodeInterpreterError, match="boot failed"):
        SmolvmInterpreter().start()
    assert commands == [["machine", "create"], ["machine", "start"], ["machine", "delete"]]
