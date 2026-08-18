import json

import pytest
from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

from dspy_interpreters import (
    CheckResult,
    ConformanceReport,
    InProcessInterpreter,
    SubprocessInterpreter,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
    check_rlm_execution_instructions,
)


def test_report_serialization():
    report = ConformanceReport((CheckResult("CI000.example", True), CheckResult("CI999.bad", False, "no")))
    assert report.failed_ids == ("CI999.bad",)
    assert json.loads(json.dumps(report.to_dict()))["results"][1]["detail"] == "no"


@pytest.mark.parametrize("factory", [InProcessInterpreter, SubprocessInterpreter])
def test_local_conformance(factory):
    report = check_interpreter(factory)
    assert report.passed, report.to_dict()
    assert check_execution_instructions(factory).passed


@pytest.mark.parametrize("factory", [InProcessInterpreter, SubprocessInterpreter])
def test_local_real_consumers(factory):
    assert check_rlm(factory).passed
    assert check_flex_facade(factory).passed


def test_in_process_capability_bookkeeping_is_not_guest_state():
    interpreter = InProcessInterpreter(tools={"old_tool": lambda: 1})
    try:
        interpreter.execute("old_tool()\n__dspy_capabilities__ = {'remembered'}\nremembered = 42")
        interpreter.tools = {"new_tool": lambda: 2}
        assert interpreter.execute("remembered") == 42
        with pytest.raises(CodeExecutionError, match="old_tool"):
            interpreter.execute("old_tool()")
    finally:
        interpreter.shutdown()


@pytest.mark.xfail(strict=True, reason="requires merged but unreleased DSPy PR #10136")
def test_rlm_uses_execution_instructions():
    assert check_rlm_execution_instructions(InProcessInterpreter).passed


def test_mutant_shared_namespace_fails_isolation():
    shared = {"__builtins__": __builtins__}

    class Mutant(InProcessInterpreter):
        def __init__(self):
            super().__init__()
            self._namespace = shared

    report = check_interpreter(Mutant)
    assert "isolation.fresh_instances" in report.failed_ids


def test_mutant_nonterminal_shutdown_fails_shutdown():
    class Mutant(InProcessInterpreter):
        def shutdown(self):
            self._ended = False

    report = check_interpreter(Mutant)
    assert "lifecycle.shutdown_is_terminal" in report.failed_ids


def test_instance_only_execution_instructions_fail_factory_metadata_check():
    class Mutant(InProcessInterpreter):
        @property
        def execution_instructions(self):
            return "Only available after construction."

    assert "execution_instructions.stable_nonempty_string" in check_execution_instructions(Mutant).failed_ids


def test_mutant_runtime_error_is_terminal_fails_taxonomy():
    class Mutant(InProcessInterpreter):
        def execute(self, code, variables=None):
            try:
                return super().execute(code, variables)
            except CodeExecutionError as exc:
                raise CodeInterpreterError(str(exc)) from exc

    assert "errors.recoverable_taxonomy" in check_interpreter(Mutant).failed_ids


def test_mutant_loses_namespace_fails_persistence():
    class Mutant(InProcessInterpreter):
        def execute(self, code, variables=None):
            result = super().execute(code, variables)
            self._namespace = {"__builtins__": __builtins__}
            return result

    assert "state.namespace_persists" in check_interpreter(Mutant).failed_ids


def test_mutant_corrupts_final_output_fails_submit():
    class Mutant(InProcessInterpreter):
        def execute(self, code, variables=None):
            result = super().execute(code, variables)
            if isinstance(result, FinalOutput):
                return FinalOutput({"wrong": result.output})
            return result

    assert "submit.typed_outputs" in check_interpreter(Mutant).failed_ids


def test_mutant_continues_after_submit_fails_termination():
    pytest.importorskip("dspy_monty_interpreter")
    from dspy_monty_interpreter import MontyInterpreter

    assert "submit.accepted_terminates_execution" in check_interpreter(MontyInterpreter).failed_ids


def test_monty_all_suites_when_extra_is_installed():
    pytest.importorskip("dspy_monty_interpreter")
    from dspy_interpreters.monty import MontyInterpreter

    report = check_interpreter(MontyInterpreter)
    assert report.passed, report.to_dict()
    assert check_execution_instructions(MontyInterpreter).passed
    assert check_rlm(MontyInterpreter).passed
    assert check_flex_facade(MontyInterpreter).passed


def test_upstream_monty_passes_rlm_but_not_flex():
    pytest.importorskip("dspy_monty_interpreter")
    from dspy_monty_interpreter import MontyInterpreter

    assert check_rlm(MontyInterpreter).passed
    assert not check_flex_facade(MontyInterpreter).passed
