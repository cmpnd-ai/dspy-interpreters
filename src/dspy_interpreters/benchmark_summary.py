from __future__ import annotations

from typing import Any


def _milliseconds(result: dict[str, Any], metric: str) -> str:
    distribution = result.get("timings_ms", {}).get(metric, {})
    median = distribution.get("median")
    p95 = distribution.get("p95")
    return "—" if median is None or p95 is None else f"{median:.2f} / {p95:.2f}"


def _mebibytes(value: int | None) -> str:
    return "—" if value is None else f"{value / (1024 * 1024):.1f}"


def render_benchmark_summary(payload: dict[str, Any]) -> str:
    lines = [
        "## Interpreter benchmark",
        "",
        "Wall-clock milliseconds are shown as p50 / p95; memory is guest-process RSS where available.",
        "",
        "| Backend | TTI p50 / p95 (ms) | Warm execute (ms) | Host tool (ms) | 1 MiB input (ms) | Guest RSS (MiB) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    failures = []
    for result in payload["results"]:
        if result.get("status") == "failed":
            lines.append(f"| {result['backend']} | failed | — | — | — | — |")
            failures.append(f"- **{result['backend']}**: `{result['error']}`")
            continue
        memory = result.get("memory_bytes", {}).get("guest_before_allocation")
        lines.append(
            "| {backend} | {tti} | {warm} | {tool} | {payload} | {memory} |".format(
                backend=result["backend"],
                tti=_milliseconds(result, "time_to_interactive"),
                warm=_milliseconds(result, "warm_execute"),
                tool=_milliseconds(result, "host_tool_round_trip"),
                payload=_milliseconds(result, "one_megabyte_variable"),
                memory=_mebibytes(memory),
            )
        )
    lines.extend(
        [
            "",
            "TTI covers construction through the first completed execution. Raw samples, p95 values, host process-tree "
            "RSS, and environment metadata are in the uploaded `interpreter-benchmark-report` artifact.",
        ]
    )
    if failures:
        lines.extend(["", "### Failures", "", *failures])
    return "\n".join(lines) + "\n"


__all__ = ["render_benchmark_summary"]
