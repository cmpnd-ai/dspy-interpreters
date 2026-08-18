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


def test_benchmark_summary_compares_timings_to_previous_results_by_backend():
    payload = {
        "results": [
            {
                "backend": "local",
                "timings_ms": {
                    "time_to_interactive": {"median": 8.0, "p95": 12.0},
                    "warm_execute": {"median": 2.5, "p95": 3.0},
                    "host_tool_round_trip": {"median": 4.0, "p95": 6.0},
                    "one_megabyte_variable": {"median": 10.0, "p95": 15.0},
                },
                "memory_bytes": {},
            }
        ]
    }
    previous_payload = {
        "results": [
            {"backend": "other", "status": "failed", "error": "irrelevant"},
            {
                "backend": "local",
                "timings_ms": {
                    "time_to_interactive": {"median": 10.0, "p95": 10.0},
                    "warm_execute": {"median": 2.0, "p95": 4.0},
                    "host_tool_round_trip": {"median": 4.0, "p95": 5.0},
                    "one_megabyte_variable": {"median": 8.0, "p95": 20.0},
                },
            },
        ]
    }

    summary = render_benchmark_summary(payload, previous_payload)

    assert "prior base-branch run; negative is faster" in summary
    assert "8.00 / 12.00 (-20.0% / +20.0%)" in summary
    assert "2.50 / 3.00 (+25.0% / -25.0%)" in summary
    assert "4.00 / 6.00 (+0.0% / +20.0%)" in summary
    assert "10.00 / 15.00 (+25.0% / -25.0%)" in summary
