from __future__ import annotations

from collections.abc import Callable
from typing import Any

import dspy
from dspy import CodeExecutionError, CodeInterpreter, CodeInterpreterError, FinalOutput
from dspy.utils.dummies import DummyLM

from dspy_interpreters.models import CheckResult, ConformanceReport

Check = Callable[[Callable[[], CodeInterpreter]], None]


def _value_is(result: Any, expected: Any) -> bool:
    """Accept native values and their REPL display form.

    ``CodeInterpreter.execute`` intentionally permits display strings (the
    historical Monty behavior) as well as native last-expression values (the
    DSPy Pyodide behavior). Consumer checks validate typed values at SUBMIT.
    """
    return result == expected or str(result) == str(expected)


def _with(factory: Callable[[], CodeInterpreter], body: Callable[[CodeInterpreter], None]) -> None:
    interpreter = factory()
    try:
        body(interpreter)
    finally:
        interpreter.shutdown()


def _protocol(factory: Callable[[], CodeInterpreter]) -> None:
    interpreter = factory()
    assert isinstance(interpreter, CodeInterpreter)
    assert isinstance(interpreter.tools, dict)
    interpreter.shutdown()


def _configure(
    interpreter: CodeInterpreter,
    *,
    tools: dict[str, Callable[..., Any]],
    output_fields: list[dict[str, Any]] | None = None,
) -> None:
    """Use optional bind when present, otherwise exercise DSPy's legacy public shape."""
    bind = getattr(interpreter, "bind", None)
    if callable(bind):
        bind(tools=tools, output_fields=output_fields)
        return
    interpreter.tools.clear()
    interpreter.tools.update(tools)
    if hasattr(interpreter, "output_fields"):
        interpreter.output_fields = output_fields  # type: ignore[attr-defined]
    if hasattr(interpreter, "_tools_registered"):
        interpreter._tools_registered = False  # type: ignore[attr-defined]


def _lifecycle(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        i.start()
        i.start()
        assert _value_is(i.execute("40 + 2"), 42)

    _with(factory, body)


def _execution(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        result = i.execute("print('marker')")
        assert "marker" in str(result)
        assert _value_is(i.execute("6 * 7"), 42)

    _with(factory, body)


def _persistence(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        i.execute("remembered = 41")
        assert _value_is(i.execute("remembered + 1"), 42)
        assert _value_is(i.execute("injected + 2", {"injected": 40}), 42)

    _with(factory, body)


def _isolation(factory: Callable[[], CodeInterpreter]) -> None:
    first = factory()
    second = factory()
    try:
        first.execute("private_value = 1")
        try:
            second.execute("private_value")
        except CodeExecutionError:
            pass
        else:
            raise AssertionError("factory instances share a namespace")
    finally:
        first.shutdown()
        second.shutdown()


def _errors(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        try:
            i.execute("if")
        except SyntaxError:
            pass
        else:
            raise AssertionError("invalid syntax did not raise SyntaxError")
        try:
            i.execute("1 / 0")
        except CodeExecutionError:
            pass
        else:
            raise AssertionError("runtime failure did not raise CodeExecutionError")
        assert _value_is(i.execute("21 * 2"), 42)

    _with(factory, body)


def _tools(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        seen: list[tuple[int, int]] = []

        def add(*, left: int, right: int) -> dict[str, int]:
            seen.append((left, right))
            return {"value": left + right}

        _configure(i, tools={"add": add})
        assert _value_is(i.execute("add(left=19, right=23)['value']"), 42)
        assert seen == [(19, 23)]

    _with(factory, body)


def _bind(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        i.execute("kept = 42")
        _configure(i, tools={"old_tool": lambda: 1})
        assert _value_is(i.execute("old_tool()"), 1)
        _configure(i, tools={"new_tool": lambda: 2})
        assert _value_is(i.execute("kept + new_tool()"), 44)
        try:
            i.execute("old_tool()")
        except CodeExecutionError:
            pass
        else:
            raise AssertionError("replaced tool remains callable")

    _with(factory, body)


def _submit(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        _configure(i, tools={})
        one = i.execute("SUBMIT(42)")
        assert isinstance(one, FinalOutput) and one.output == {"output": 42}
        _configure(
            i,
            tools={},
            output_fields=[{"name": "answer", "type": "str"}, {"name": "score", "type": "int"}],
        )
        many = i.execute("SUBMIT(answer='yes', score=42)")
        assert isinstance(many, FinalOutput) and many.output == {"answer": "yes", "score": 42}
        try:
            i.execute("SUBMIT('missing')")
        except CodeExecutionError:
            pass
        else:
            raise AssertionError("invalid typed submission was accepted")
        assert _value_is(i.execute("6 * 7"), 42)

    _with(factory, body)


def _submit_terminates(factory: Callable[[], CodeInterpreter]) -> None:
    def body(i: CodeInterpreter) -> None:
        calls = 0

        def after_submit() -> None:
            nonlocal calls
            calls += 1

        _configure(i, tools={"after_submit": after_submit})
        result = i.execute("SUBMIT(42)\nafter_submit()")
        assert isinstance(result, FinalOutput)
        assert calls == 0, "execution continued after an accepted SUBMIT"

    _with(factory, body)


def _execution_instructions(factory: Callable[[], CodeInterpreter]) -> None:
    interpreter = factory()
    try:
        first = getattr(interpreter, "execution_instructions", None)
        second = getattr(interpreter, "execution_instructions", None)
        assert isinstance(first, str) and first.strip()
        assert second == first
    finally:
        interpreter.shutdown()


def _native_bind(factory: Callable[[], CodeInterpreter]) -> None:
    interpreter = factory()
    try:
        bind = getattr(interpreter, "bind", None)
        assert callable(bind), "interpreter does not implement bind"
        tools = {"first": lambda: 1}
        fields = [{"name": "answer", "type": "str"}]
        bind(tools=tools, output_fields=fields)
        tools["second"] = lambda: 2
        fields[0]["name"] = "changed"
        assert set(interpreter.tools) == {"first"}
        assert _value_is(interpreter.execute("first()"), 1)
        bind(tools={"second": lambda: 2}, output_fields=None)
        assert set(interpreter.tools) == {"second"}
        try:
            interpreter.execute("first()")
        except CodeExecutionError:
            pass
        else:
            raise AssertionError("bind did not revoke the previous tool")
    finally:
        interpreter.shutdown()


def _shutdown(factory: Callable[[], CodeInterpreter]) -> None:
    i = factory()
    i.shutdown()
    i.shutdown()
    for operation in (i.start, lambda: i.execute("1")):
        try:
            operation()
        except CodeInterpreterError:
            pass
        else:
            raise AssertionError("shutdown was not terminal")


INTERPRETER_CHECKS: tuple[tuple[str, Check], ...] = (
    ("protocol.public_shape", _protocol),
    ("lifecycle.lazy_idempotent_start", _lifecycle),
    ("execution.python_and_output", _execution),
    ("state.namespace_persists", _persistence),
    ("isolation.fresh_instances", _isolation),
    ("errors.recoverable_taxonomy", _errors),
    ("tools.host_call_round_trips", _tools),
    ("tools.removal_revokes_authority", _bind),
    ("submit.typed_outputs", _submit),
    ("submit.accepted_terminates_execution", _submit_terminates),
    ("lifecycle.shutdown_is_terminal", _shutdown),
)

EXECUTION_INSTRUCTIONS_CHECKS: tuple[tuple[str, Check], ...] = (
    ("execution_instructions.stable_nonempty_string", _execution_instructions),
)

BIND_CHECKS: tuple[tuple[str, Check], ...] = (("bind.atomic_replacement", _native_bind),)

# Backward-compatible spelling for the pytest adapter and early adopters.
PUBLIC_CHECKS = INTERPRETER_CHECKS


def _run_checks(
    checks: tuple[tuple[str, Check], ...],
    factory: Callable[[], CodeInterpreter],
    on_fail: str,
) -> ConformanceReport:
    if on_fail not in {"collect", "raise"}:
        raise ValueError("on_fail must be 'collect' or 'raise'")
    results: list[CheckResult] = []
    for check_id, check in checks:
        try:
            check(factory)
        except Exception as exc:
            result = CheckResult(check_id, False, f"{type(exc).__name__}: {exc}")
            results.append(result)
            if on_fail == "raise":
                raise AssertionError(f"{check_id} failed: {result.detail}") from exc
        else:
            results.append(CheckResult(check_id, True))
    return ConformanceReport(tuple(results))


def check_interpreter(factory: Callable[[], CodeInterpreter], on_fail: str = "collect") -> ConformanceReport:
    """Run backend-level checks using only the public interpreter surface."""
    return _run_checks(INTERPRETER_CHECKS, factory, on_fail)


def check_execution_instructions(
    factory: Callable[[], CodeInterpreter], on_fail: str = "collect"
) -> ConformanceReport:
    """Check the optional stable execution-instructions extension."""
    return _run_checks(EXECUTION_INSTRUCTIONS_CHECKS, factory, on_fail)


def check_bind(factory: Callable[[], CodeInterpreter], on_fail: str = "collect") -> ConformanceReport:
    """Check the optional invocation-scoped binding extension."""
    return _run_checks(BIND_CHECKS, factory, on_fail)


def _rlm_real_consumer(factory: Callable[[], CodeInterpreter]) -> None:
    instances: list[CodeInterpreter] = []
    shutdowns: list[CodeInterpreter] = []

    class RecordingInterpreter:
        def __init__(self, inner: CodeInterpreter) -> None:
            self.inner = inner

        @property
        def tools(self) -> dict[str, Callable[..., Any]]:
            return self.inner.tools

        def start(self) -> None:
            self.inner.start()

        def execute(self, code: str, variables: dict[str, Any] | None = None) -> Any:
            return self.inner.execute(code, variables)

        def shutdown(self) -> None:
            shutdowns.append(self)
            self.inner.shutdown()

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

    def recording_factory() -> CodeInterpreter:
        instance = RecordingInterpreter(factory())
        instances.append(instance)
        return instance

    host_calls: list[tuple[int, int]] = []

    def add(*, left: int, right: int) -> int:
        host_calls.append((left, right))
        return left + right

    class SubLM:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        def __call__(self, prompt: str) -> list[str]:
            self.prompts.append(prompt)
            return ["brokered"]

    class Actions(dspy.Predict):
        def __init__(self, signature: type[dspy.Signature]) -> None:
            super().__init__(signature)
            self.calls: list[dict[str, Any]] = []
            self.actions = (
                dspy.Prediction(
                    reasoning="exercise host capabilities",
                    code=(
                        "partial = add(left=20, right=22)\n"
                        "semantic = llm_query(prompt='classify')\n"
                        "print(partial, semantic)"
                    ),
                ),
                dspy.Prediction(reasoning="submit typed result", code="SUBMIT(answer=f'{partial}:{semantic}')"),
            )

        def forward(self, **kwargs: Any) -> dspy.Prediction:
            self.calls.append(kwargs)
            return self.actions[len(self.calls) - 1]

    sub_lm = SubLM()
    rlm = dspy.RLM(
        "question: str -> answer: str",
        max_iters=2,
        tools=[add],
        sub_lm=sub_lm,
        interpreter_factory=recording_factory,
    )
    actions = Actions(rlm.generate_action.signature)
    rlm.generate_action = actions
    result = rlm(question="compute")
    assert result.answer == "42:brokered"
    assert host_calls == [(20, 22)]
    assert sub_lm.prompts == ["classify"]
    assert len(instances) == 1
    assert shutdowns == instances
    if getattr(instances[0], "execution_instructions", ""):
        action_signature = actions.calls[0]["signature"]
        assert "Code interpreter execution environment:" in action_signature.instructions
        assert "execution_instructions" not in action_signature.input_fields
    else:
        assert "signature" not in actions.calls[0]


RLM_CHECKS: tuple[tuple[str, Check], ...] = (("rlm.real_consumer_flow", _rlm_real_consumer),)


def check_rlm(factory: Callable[[], CodeInterpreter], on_fail: str = "collect") -> ConformanceReport:
    """Run a deterministic real ``dspy.RLM`` through the backend factory."""
    return _run_checks(RLM_CHECKS, factory, on_fail)


def _flex_facade_real_consumer(factory: Callable[[], CodeInterpreter]) -> None:
    class FlexSignature(dspy.Signature):
        value: int = dspy.InputField()
        result: int = dspy.OutputField()

    def add_two(*, value: int) -> int:
        return value + 2

    module_src = """
class ConformanceModule(dspy.Module):
    def __init__(self):
        super().__init__()
        self.solve = dspy.Predict("value: int -> result: int")

    def forward(self, **inputs):
        predicted = self.solve(value=inputs["value"])
        return dspy.Prediction(result=add_two(value=predicted.result))
""".strip()

    program = dspy.Flex(FlexSignature, tools=[add_two], interpreter_factory=factory)
    program._bind_code(module_src)
    with dspy.context(lm=DummyLM([{"result": "40"}])):
        result = program(value=20)
    assert result.result == 42

    state = program.dump_state()
    assert state["module_src"] == module_src
    assert "interpreter" not in str(state).lower()
    restored = dspy.Flex(FlexSignature, tools=[add_two], interpreter_factory=factory)
    restored.load_state(state)
    with dspy.context(lm=DummyLM([{"result": "40"}])):
        assert restored(value=20).result == 42


FLEX_CHECKS: tuple[tuple[str, Check], ...] = (("flex.facade_real_consumer_flow", _flex_facade_real_consumer),)


def check_flex_facade(factory: Callable[[], CodeInterpreter], on_fail: str = "collect") -> ConformanceReport:
    """Execute an actual optimized Flex facade, host predictor, and host tool."""
    return _run_checks(FLEX_CHECKS, factory, on_fail)
