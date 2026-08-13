import pytest
from dspy import CodeInterpreterError

from dspy_interpreters import (
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)

pytest.importorskip("ipykernel")

from dspy_interpreters.ikernel import IKernelInterpreter, IPythonInterpreter


def test_ikernel_alias():
    assert IKernelInterpreter is IPythonInterpreter


@pytest.mark.parametrize(
    "suite",
    [check_interpreter, check_bind, check_execution_instructions, check_rlm, check_flex_facade],
)
def test_ipython_kernel_conformance(suite):
    report = suite(IPythonInterpreter)
    assert report.passed, report.to_dict()


def test_ipython_timeout_ends_session():
    interpreter = IPythonInterpreter(execution_timeout=0.2)
    try:
        with pytest.raises(CodeInterpreterError, match="timed out"):
            interpreter.execute("while True: pass")
        with pytest.raises(CodeInterpreterError, match="shut down"):
            interpreter.execute("1")
    finally:
        interpreter.shutdown()
