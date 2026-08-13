from __future__ import annotations

import math
import os
import platform
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from dspy import CodeInterpreter


@dataclass(frozen=True)
class Distribution:
    samples: tuple[float, ...]
    median: float
    p95: float
    minimum: float
    maximum: float

    @classmethod
    def from_samples(cls, samples: list[float]) -> Distribution:
        ordered = sorted(samples)
        p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
        return cls(tuple(samples), statistics.median(samples), ordered[p95_index], ordered[0], ordered[-1])


@dataclass(frozen=True)
class BenchmarkReport:
    backend: str
    environment: dict[str, Any]
    timings_ms: dict[str, Distribution]
    memory_bytes: dict[str, int | None]

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "environment": self.environment,
            "timings_ms": {name: asdict(value) for name, value in self.timings_ms.items()},
            "memory_bytes": self.memory_bytes,
        }


def _timed(operation: Callable[[], Any]) -> tuple[float, Any]:
    started = time.perf_counter_ns()
    value = operation()
    return (time.perf_counter_ns() - started) / 1_000_000, value


def _process_tree_rss() -> int | None:
    try:
        import psutil

        process = psutil.Process()
        return process.memory_info().rss + sum(
            child.memory_info().rss for child in process.children(recursive=True) if child.is_running()
        )
    except Exception:
        return None


def _guest_rss(interpreter: CodeInterpreter) -> int | None:
    code = (
        "import os as _dspy_bench_os\n"
        "int(open('/proc/self/statm').read().split()[1]) * _dspy_bench_os.sysconf('SC_PAGE_SIZE')"
    )
    try:
        value = interpreter.execute(code)
        return int(value)
    except Exception:
        return None


def benchmark_interpreter(
    factory: Callable[[], CodeInterpreter],
    *,
    name: str | None = None,
    cold_runs: int = 1,
    warm_runs: int = 20,
    allocation_bytes: int = 8 * 1024 * 1024,
) -> BenchmarkReport:
    """Measure reproducible lifecycle, execution, callback, and memory scenarios.

    Results are descriptive rather than conformance gates. Provider and machine
    variance is retained as raw samples and summarized with median and p95.
    """
    if cold_runs < 1 or warm_runs < 1 or allocation_bytes < 0:
        raise ValueError("cold_runs and warm_runs must be positive; allocation_bytes must be non-negative")

    timings: dict[str, list[float]] = {
        "construction": [],
        "start": [],
        "first_execute": [],
        "time_to_interactive": [],
        "warm_execute": [],
        "host_tool_round_trip": [],
        "one_megabyte_variable": [],
        "shutdown": [],
    }
    for _ in range(cold_runs):
        construction, interpreter = _timed(factory)
        timings["construction"].append(construction)
        try:
            startup, _ = _timed(interpreter.start)
            timings["start"].append(startup)
            first, result = _timed(lambda current=interpreter: current.execute("40 + 2"))
            if str(result) != "42":
                raise AssertionError(f"benchmark sanity check returned {result!r}")
            timings["first_execute"].append(first)
            timings["time_to_interactive"].append(construction + startup + first)
        finally:
            shutdown, _ = _timed(interpreter.shutdown)
            timings["shutdown"].append(shutdown)

    interpreter = factory()
    memory_before = _process_tree_rss()
    interpreter.start()
    memory_started = _process_tree_rss()
    guest_before = _guest_rss(interpreter)
    try:
        for _ in range(warm_runs):
            elapsed, result = _timed(lambda: interpreter.execute("6 * 7"))
            if str(result) != "42":
                raise AssertionError(f"benchmark sanity check returned {result!r}")
            timings["warm_execute"].append(elapsed)

        def add(*, left: int, right: int) -> int:
            return left + right

        bind = getattr(interpreter, "bind", None)
        if callable(bind):
            bind(tools={"add": add}, output_fields=None)
        else:
            interpreter.tools.clear()
            interpreter.tools["add"] = add
            if hasattr(interpreter, "_tools_registered"):
                interpreter._tools_registered = False  # type: ignore[attr-defined]
        for _ in range(warm_runs):
            elapsed, result = _timed(lambda: interpreter.execute("add(left=19, right=23)"))
            if str(result) != "42":
                raise AssertionError(f"tool benchmark sanity check returned {result!r}")
            timings["host_tool_round_trip"].append(elapsed)

        payload = "x" * (1024 * 1024)
        for _ in range(min(warm_runs, 5)):
            elapsed, result = _timed(lambda: interpreter.execute("len(payload)", {"payload": payload}))
            if str(result) != str(len(payload)):
                raise AssertionError(f"payload benchmark sanity check returned {result!r}")
            timings["one_megabyte_variable"].append(elapsed)

        if allocation_bytes:
            interpreter.execute(f"_dspy_benchmark_allocation = 'x' * {allocation_bytes}")
        guest_allocated = _guest_rss(interpreter)
        memory_allocated = _process_tree_rss()
    finally:
        interpreter.shutdown()

    return BenchmarkReport(
        backend=name or getattr(factory, "__name__", type(factory).__name__),
        environment={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "cold_runs": cold_runs,
            "warm_runs": warm_runs,
            "allocation_bytes": allocation_bytes,
        },
        timings_ms={metric: Distribution.from_samples(samples) for metric, samples in timings.items()},
        memory_bytes={
            "host_process_tree_before_start": memory_before,
            "host_process_tree_after_start": memory_started,
            "host_process_tree_after_allocation": memory_allocated,
            "guest_before_allocation": guest_before,
            "guest_after_allocation": guest_allocated,
        },
    )


__all__ = ["BenchmarkReport", "Distribution", "benchmark_interpreter"]
