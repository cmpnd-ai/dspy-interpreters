import json

import pytest
from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

from dspy_interpreters import (
    CheckResult,
    ConformanceReport,
    LocalInterpreter,
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)


def test_report_serialization():
    report = ConformanceReport((CheckResult("CI000.example", True), CheckResult("CI999.bad", False, "no")))
    assert report.failed_ids == ("CI999.bad",)
    assert json.loads(json.dumps(report.to_dict()))["results"][1]["detail"] == "no"


def test_local_conformance():
    report = check_interpreter(LocalInterpreter)
    assert report.passed, report.to_dict()
    assert check_bind(LocalInterpreter).passed
    assert check_execution_instructions(LocalInterpreter).passed


def test_local_real_consumers():
    assert check_rlm(LocalInterpreter).passed
    assert check_flex_facade(LocalInterpreter).passed


def test_mutant_shared_namespace_fails_isolation():
    shared = {"__builtins__": __builtins__}

    class Mutant(LocalInterpreter):
        def __init__(self):
            super().__init__()
            self._namespace = shared

    report = check_interpreter(Mutant)
    assert "isolation.fresh_instances" in report.failed_ids


def test_mutant_nonterminal_shutdown_fails_shutdown():
    class Mutant(LocalInterpreter):
        def shutdown(self):
            self._ended = False

    report = check_interpreter(Mutant)
    assert "lifecycle.shutdown_is_terminal" in report.failed_ids


def test_mutant_bind_leaks_old_tool_fails_bind():
    class Mutant(LocalInterpreter):
        def bind(self, *, tools, output_fields=None):
            merged = dict(self.tools)
            merged.update(tools)
            super().bind(tools=merged, output_fields=output_fields)

    report = check_interpreter(Mutant)
    assert "tools.removal_revokes_authority" in report.failed_ids


def test_mutant_runtime_error_is_terminal_fails_taxonomy():
    class Mutant(LocalInterpreter):
        def execute(self, code, variables=None):
            try:
                return super().execute(code, variables)
            except CodeExecutionError as exc:
                raise CodeInterpreterError(str(exc)) from exc

    assert "errors.recoverable_taxonomy" in check_interpreter(Mutant).failed_ids


def test_mutant_loses_namespace_fails_persistence():
    class Mutant(LocalInterpreter):
        def execute(self, code, variables=None):
            result = super().execute(code, variables)
            self._namespace = {"__builtins__": __builtins__}
            return result

    assert "state.namespace_persists" in check_interpreter(Mutant).failed_ids


def test_mutant_corrupts_final_output_fails_submit():
    class Mutant(LocalInterpreter):
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
    assert check_bind(MontyInterpreter).passed
    assert check_execution_instructions(MontyInterpreter).passed
    assert check_rlm(MontyInterpreter).passed
    assert check_flex_facade(MontyInterpreter).passed


def test_upstream_monty_passes_rlm_but_not_flex():
    pytest.importorskip("dspy_monty_interpreter")
    from dspy_monty_interpreter import MontyInterpreter

    assert check_rlm(MontyInterpreter).passed
    assert not check_flex_facade(MontyInterpreter).passed
