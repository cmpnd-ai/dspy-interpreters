from dspy_interpreters.benchmark_summary import render_benchmark_summary


def test_benchmark_summary_renders_results_and_failures():
    payload = {
        "results": [
            {
                "backend": "local",
                "timings_ms": {
                    "time_to_interactive": {"median": 1.25, "p95": 1.5},
                    "warm_execute": {"median": 0.5, "p95": 0.6},
                    "host_tool_round_trip": {"median": 0.75, "p95": 0.9},
                    "one_megabyte_variable": {"median": 2.0, "p95": 2.5},
                },
                "memory_bytes": {"guest_before_allocation": 10 * 1024 * 1024},
            },
            {"backend": "remote", "status": "failed", "error": "not authenticated"},
        ]
    }

    summary = render_benchmark_summary(payload)

    assert "| local | 1.25 / 1.50 | 0.50 / 0.60 | 0.75 / 0.90 | 2.00 / 2.50 | 10.0 |" in summary
    assert "| remote | failed" in summary
    assert "not authenticated" in summary
