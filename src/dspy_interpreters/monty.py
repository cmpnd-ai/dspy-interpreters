from __future__ import annotations

import ast
import io
import tokenize
from typing import Any

from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

try:
    from dspy_monty_interpreter import MontyInterpreter as _MontyInterpreter
    from dspy_monty_interpreter import MountDir
    from pydantic_monty import MontyRuntimeError
except ImportError as exc:  # pragma: no cover - exercised by packaging, not an installed extra
    raise ImportError("Install dspy-interpreters[monty] to use MontyInterpreter") from exc


_TERMINATING_SUBMIT = "_dspy_interpreters_terminating_submit"


class _SubmitSignal(BaseException):
    """Unwind Monty execution after an accepted submission."""


def _route_submit_to_terminating_tool(code: str) -> str:
    """Route references to the interpreter-provided SUBMIT through our host tool."""
    tokens = tokenize.generate_tokens(io.StringIO(code).readline)
    return tokenize.untokenize(
        (token.type, _TERMINATING_SUBMIT if token.type == tokenize.NAME and token.string == "SUBMIT" else token.string)
        for token in tokens
    )


class _LowerFlexSource(ast.NodeTransformer):
    """Lower the facade's marker inheritance to Monty's supported syntax."""

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node = self.generic_visit(node)
        is_flex_module = any(
            isinstance(base, ast.Attribute)
            and isinstance(base.value, ast.Name)
            and base.value.id == "dspy"
            and base.attr == "Module"
            for base in node.bases
        )
        if is_flex_module:
            node.bases = []
        return node

    def visit_Expr(self, node: ast.Expr) -> ast.stmt:
        call = node.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "__init__"
            and isinstance(call.func.value, ast.Call)
            and isinstance(call.func.value.func, ast.Name)
            and call.func.value.func.id == "super"
        ):
            return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        node = self.generic_visit(node)
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Attribute)
            and isinstance(node.targets[0].value, ast.Name)
            and node.targets[0].value.id == "self"
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "dspy"
            and node.value.func.attr
            in {"Predict", "ChainOfThought", "RLM", "CodeAct", "ProgramOfThought", "ReAct", "ReActV2"}
        ):
            signature = node.value.args[0] if node.value.args else ast.Constant(None)
            config = ast.Dict(
                keys=[ast.Constant(keyword.arg) for keyword in node.value.keywords],
                values=[
                    ast.Call(func=ast.Name("_dspy_enc", ast.Load()), args=[keyword.value], keywords=[])
                    for keyword in node.value.keywords
                ],
            )
            host_call = ast.Call(
                func=ast.Name("_dspy_host", ast.Load()),
                args=[ast.Constant("__dspy_construct__")],
                keywords=[
                    ast.keyword(arg="kind", value=ast.Constant(node.value.func.attr)),
                    ast.keyword(arg="signature", value=signature),
                    ast.keyword(arg="attr_name", value=ast.Constant(node.targets[0].attr)),
                    ast.keyword(arg="kwargs", value=config),
                ],
            )
            node.value = ast.Call(func=ast.Name("_dspy_callable_proxy", ast.Load()), args=[host_call], keywords=[])
        return node


def _lower_flex_source(code: str) -> str:
    if "dspy.Module" not in code:
        return code
    tree = _LowerFlexSource().visit(ast.parse(code))
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


class MontyInterpreter(_MontyInterpreter):
    """Conforming adapter over ``dspy-monty-interpreter``.

    The wrapper corrects the recoverable runtime-error class, normalizes
    untyped SUBMIT, and makes shutdown terminal. Execution and isolation remain
    owned by Monty.
    """

    execution_instructions = (
        "Code runs in Monty's restricted Python runtime in worker subprocesses. "
        "State persists during this session. Only Monty's supported Python and standard-library subset is "
        "available; network, environment, and filesystem access are denied unless explicitly mounted. "
        "Use provided host tools for external capabilities."
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._dspy_ended = False

    def _check_active(self) -> None:
        if self._dspy_ended:
            raise CodeInterpreterError("MontyInterpreter session has been shut down")

    def start(self) -> None:
        self._check_active()
        super().start()

    def execute(self, code: str, variables: dict[str, Any] | None = None) -> Any:
        self._check_active()
        # DSPy's facade needs only an attribute container, but its portable shim
        # currently constructs one through stdlib ``types``, which Monty omits.
        # Lower that single operation without changing facade semantics.
        if "import types as _dspy_types" in code and '_dspy_types.ModuleType("dspy")' in code:
            code = code.replace("import types as _dspy_types\n", "")
            code = code.replace(
                'object.__setattr__(self, "_fields", dict(_fields))',
                "self._fields = dict(_fields)\n"
                "        for _field_name, _field_value in _fields.items():\n"
                "            setattr(self, _field_name, _field_value)",
            )
            code = code.replace('object.__getattribute__(self, "_fields")', "self._fields")
            code = code.replace('object.__setattr__(self, "_handle", _handle)', "self._handle = _handle")
            code = code.replace('object.__getattribute__(self, "_handle")', "self._handle")
            code = code.replace(
                '_dspy = _dspy_types.ModuleType("dspy")',
                "class _DspyFacadeModule:\n    pass\n\n_dspy = _DspyFacadeModule()",
            )
            code = code.replace(
                "return globals()[_fn](**_kw)",
                "if _fn == '__dspy_construct__':\n"
                "        return __dspy_construct__(**_kw)\n"
                "    if _fn == '__dspy_call__':\n"
                "        return __dspy_call__(**_kw)\n"
                "    raise RuntimeError('unknown DSPy bridge function: ' + _fn)",
            )
            code = code.replace('if "__dspy_construct__" in globals():', "if True:")
            code = code.replace('_dspy_sys.modules["dspy"] = _dspy', "pass")
            code += """

def _dspy_callable_proxy(_handle):
    def _call(**_inputs):
        _out = _dspy_host("__dspy_call__", handle=_handle, inputs=_inputs)
        return _DspyPrediction(**(_out or {}))
    return _call
"""
        code = _lower_flex_source(code)
        submission: list[FinalOutput] = []

        def terminating_submit(*args: Any, **kwargs: Any) -> None:
            if kwargs:
                output: Any = dict(kwargs)
            elif args and self.output_fields is not None:
                field_names = [field["name"] for field in self.output_fields]
                if len(args) == 1 and isinstance(args[0], dict) and set(args[0]).issubset(field_names):
                    output = dict(args[0])
                else:
                    output = dict(zip(field_names, args, strict=False))
            elif len(args) == 1:
                output = args[0]
            else:
                output = None
            final = self._normalize_submission(FinalOutput(output))
            submission.append(final)
            raise _SubmitSignal()

        previous_submit_tool = self.tools.get(_TERMINATING_SUBMIT)
        self.tools[_TERMINATING_SUBMIT] = terminating_submit
        try:
            result = super().execute(_route_submit_to_terminating_tool(code), variables)
        except CodeInterpreterError as exc:
            if submission:
                self._has_state = True
                return submission[0]
            if isinstance(exc.__cause__, MontyRuntimeError):
                raise CodeExecutionError(str(exc)) from exc
            raise
        finally:
            if previous_submit_tool is None:
                self.tools.pop(_TERMINATING_SUBMIT, None)
            else:
                self.tools[_TERMINATING_SUBMIT] = previous_submit_tool
        if submission:
            return submission[0]
        if isinstance(result, FinalOutput):
            return self._normalize_submission(result)
        return result

    def _normalize_submission(self, result: FinalOutput) -> FinalOutput:
        if self.output_fields is None and not isinstance(result.output, dict):
            result = FinalOutput({"output": result.output})
        if self.output_fields is not None:
            required = {field["name"] for field in self.output_fields}
            if not isinstance(result.output, dict) or set(result.output) != required:
                raise CodeExecutionError(f"SUBMIT must provide exactly these fields: {sorted(required)}")
        return result

    def shutdown(self) -> None:
        if not self._dspy_ended:
            super().shutdown()
            self._dspy_ended = True


__all__ = ["MontyInterpreter", "MountDir"]
