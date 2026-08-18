import os
import time

import pytest
from dspy import CodeExecutionError, CodeInterpreterError

from dspy_interpreters import SubprocessInterpreter


def test_runs_outside_host_process_and_captures_guest_stdout(capsys):
    interpreter = SubprocessInterpreter()
    try:
        assert interpreter.execute("import os\nos.getpid()") != os.getpid()
        assert interpreter.execute("print('guest only')") == "guest only"
        assert capsys.readouterr().out == ""
    finally:
        interpreter.shutdown()


def test_tool_failure_is_recoverable():
    def fail():
        raise RuntimeError("host failed")

    interpreter = SubprocessInterpreter(tools={"fail": fail})
    try:
        with pytest.raises(CodeExecutionError, match="host failed"):
            interpreter.execute("fail()")
        assert interpreter.execute("6 * 7") == 42
    finally:
        interpreter.shutdown()


def test_timeout_terminates_worker_and_session():
    interpreter = SubprocessInterpreter(execution_timeout=0.1)
    with pytest.raises(CodeInterpreterError, match="exceeded execution timeout"):
        interpreter.execute("import time\ntime.sleep(10)")
    with pytest.raises(CodeInterpreterError, match="shut down"):
        interpreter.execute("1")
    interpreter.shutdown()


def test_host_tool_within_execution_timeout():
    def slow() -> int:
        time.sleep(0.08)
        return 42

    interpreter = SubprocessInterpreter(tools={"slow": slow}, execution_timeout=0.2)
    try:
        assert interpreter.execute("slow()") == 42
    finally:
        interpreter.shutdown()


def test_non_json_input_is_recoverable():
    interpreter = SubprocessInterpreter()
    try:
        with pytest.raises(CodeInterpreterError, match="JSON-compatible"):
            interpreter.execute("value", {"value": object()})
        assert interpreter.execute("6 * 7") == 42
    finally:
        interpreter.shutdown()
