from dspy_interpreters import LocalInterpreter
from dspy_interpreters.benchmarks import benchmark_interpreter


def test_local_benchmark_has_raw_samples_and_memory():
    report = benchmark_interpreter(LocalInterpreter, cold_runs=1, warm_runs=2, allocation_bytes=1024)
    assert report.backend == "LocalInterpreter"
    assert len(report.timings_ms["warm_execute"].samples) == 2
    assert len(report.timings_ms["host_tool_round_trip"].samples) == 2
    assert report.timings_ms["time_to_interactive"].median >= 0
    assert "guest_after_allocation" in report.memory_bytes
