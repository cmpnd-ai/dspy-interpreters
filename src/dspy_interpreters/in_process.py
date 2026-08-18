from __future__ import annotations

import ast
import contextlib
import inspect
import io
import sys
from collections.abc import Callable
from typing import Any

from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput


class _Submission(BaseException):
    def __init__(self, value: Any) -> None:
        self.value = value


class InProcessInterpreter:
    """Small trusted CodeInterpreter that executes inside the DSPy process."""

    execution_instructions = (
        "Code runs as trusted Python in the host process. State, imports, functions, and variables persist "
        "for this session. Host tools and SUBMIT are available as global functions."
    )

    def __init__(
        self,
        tools: dict[str, Callable[..., Any]] | None = None,
        output_fields: list[dict[str, Any]] | None = None,
    ) -> None:
        self.tools = dict(tools or {})
        self.output_fields = None if output_fields is None else [dict(field) for field in output_fields]
        self._namespace: dict[str, Any] = {"__builtins__": __builtins__}
        self._capabilities: set[str] = set()
        self._started = False
        self._ended = False

    def start(self) -> None:
        if self._ended:
            raise CodeInterpreterError("interpreter session has been shut down")
        self._started = True

    def _submit(self, *args: Any, **kwargs: Any) -> None:
        if self.output_fields is None:
            signature = inspect.Signature([inspect.Parameter("value", inspect.Parameter.POSITIONAL_OR_KEYWORD)])
            value = signature.bind(*args, **kwargs).arguments["value"]
            raise _Submission({"output": value})
        names = [field["name"] for field in self.output_fields]
        signature = inspect.Signature(
            [inspect.Parameter(name, inspect.Parameter.POSITIONAL_OR_KEYWORD) for name in names]
        )
        values = signature.bind(*args, **kwargs).arguments
        raise _Submission(dict(values))

    def execute(self, code: str, variables: dict[str, Any] | None = None) -> Any:
        self.start()
        if variables:
            if any(not isinstance(name, str) or not name.isidentifier() for name in variables):
                raise CodeInterpreterError("variable names must be Python identifiers")
            self._namespace.update(variables)
        # Refresh capabilities on every execution so replacement revokes names.
        for name in self._capabilities:
            self._namespace.pop(name, None)
        self._capabilities = set(self.tools) | {"SUBMIT"}
        self._namespace.update(self.tools)
        self._namespace["SUBMIT"] = self._submit
        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError:
            raise
        stdout = io.StringIO()
        host_dspy_module = sys.modules.get("dspy")
        try:
            with contextlib.redirect_stdout(stdout):
                value = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    prefix = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(compile(prefix, "<interpreter>", "exec"), self._namespace)
                    value = eval(compile(ast.Expression(tree.body[-1].value), "<interpreter>", "eval"), self._namespace)
                else:
                    exec(compile(tree, "<interpreter>", "exec"), self._namespace)
        except _Submission as submission:
            return FinalOutput(submission.value)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CodeExecutionError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            if host_dspy_module is None:
                sys.modules.pop("dspy", None)
            else:
                sys.modules["dspy"] = host_dspy_module
        output = stdout.getvalue().rstrip("\n")
        return value if value is not None else (output or None)

    def shutdown(self) -> None:
        self._ended = True
        self._namespace.clear()
