from dspy_interpreters import InProcessInterpreter, SubprocessInterpreter
from dspy_interpreters.benchmarks import benchmark_interpreter


def test_local_benchmark_has_raw_samples_and_memory():
    report = benchmark_interpreter(InProcessInterpreter, cold_runs=1, warm_runs=2, allocation_bytes=1024)
    assert report.backend == "InProcessInterpreter"
    assert len(report.timings_ms["warm_execute"].samples) == 2
    assert len(report.timings_ms["host_tool_round_trip"].samples) == 2
    assert report.timings_ms["time_to_interactive"].median >= 0
    assert "guest_after_allocation" in report.memory_bytes


def test_subprocess_benchmark_smoke():
    report = benchmark_interpreter(SubprocessInterpreter, cold_runs=1, warm_runs=2, allocation_bytes=1024)
    assert report.backend == "SubprocessInterpreter"
    assert report.timings_ms["warm_execute"].median >= 0


def test_benchmark_refreshes_legacy_tool_registration():
    class LegacyInterpreter:
        def __init__(self):
            self.tools = {}
            self._tools_registered = False
            self._registered_tools = set()

        def start(self):
            pass

        def execute(self, code, variables=None):
            if not self._tools_registered:
                self._registered_tools = set(self.tools)
                self._tools_registered = True
            if code in {"40 + 2", "6 * 7"} or code.startswith("len(payload)"):
                return 42 if code != "len(payload)" else len(variables["payload"])
            if code.startswith("add("):
                assert "add" in self._registered_tools
                return 42
            if "/proc/self/statm" in code:
                return 0
            return None

        def shutdown(self):
            pass

    report = benchmark_interpreter(LegacyInterpreter, cold_runs=1, warm_runs=1, allocation_bytes=0)
    assert report.timings_ms["host_tool_round_trip"].median >= 0
