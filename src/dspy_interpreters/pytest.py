from __future__ import annotations

from collections.abc import Callable

from dspy import CodeInterpreter

from dspy_interpreters.checks import PUBLIC_CHECKS


def interpreter_params(factory: Callable[[], CodeInterpreter]):
    """Return pytest parameters, one per stable public check ID."""
    import pytest

    return [pytest.param(check, factory, id=check_id) for check_id, check in PUBLIC_CHECKS]


def parametrize_interpreter(factory: Callable[[], CodeInterpreter]):
    """Decorator parametrizing a test accepting ``check`` and ``factory``."""
    import pytest

    return pytest.mark.parametrize(("check", "factory"), interpreter_params(factory))
