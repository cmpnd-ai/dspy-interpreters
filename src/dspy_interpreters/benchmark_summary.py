from __future__ import annotations

from typing import Any


def _milliseconds(result: dict[str, Any], metric: str) -> str:
    distribution = result.get("timings_ms", {}).get(metric, {})
    median = distribution.get("median")
    p95 = distribution.get("p95")
    return "—" if median is None or p95 is None else f"{median:.2f} / {p95:.2f}"


def _timing_change(result: dict[str, Any], previous: dict[str, Any] | None, metric: str) -> str:
    if previous is None:
        return ""
    current_distribution = result.get("timings_ms", {}).get(metric, {})
    previous_distribution = previous.get("timings_ms", {}).get(metric, {})
    changes = []
    for statistic in ("median", "p95"):
        current = current_distribution.get(statistic)
        prior = previous_distribution.get(statistic)
        if current is None or prior in (None, 0):
            return " (—)"
        changes.append((current / prior - 1) * 100)
    return f" ({changes[0]:+.1f}% / {changes[1]:+.1f}%)"


def _mebibytes(value: int | None) -> str:
    return "—" if value is None else f"{value / (1024 * 1024):.1f}"


def render_benchmark_summary(payload: dict[str, Any], previous_payload: dict[str, Any] | None = None) -> str:
    previous_results = (
        {result["backend"]: result for result in previous_payload["results"]} if previous_payload else {}
    )
    lines = [
        "## Interpreter benchmark",
        "",
        "Wall-clock milliseconds are shown as p50 / p95; memory is guest-process RSS where available.",
    ]
    if previous_payload:
        lines.append("Timing changes in parentheses are versus the prior base-branch run; negative is faster.")
    lines.extend([
        "",
        "| Backend | TTI p50 / p95 (ms) | Warm execute (ms) | Host tool (ms) | 1 MiB input (ms) | Guest RSS (MiB) |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    failures = []
    for result in payload["results"]:
        if result.get("status") == "failed":
            lines.append(f"| {result['backend']} | failed | — | — | — | — |")
            failures.append(f"- **{result['backend']}**: `{result['error']}`")
            continue
        previous = previous_results.get(result["backend"])
        memory = result.get("memory_bytes", {}).get("guest_before_allocation")
        lines.append(
            "| {backend} | {tti} | {warm} | {tool} | {payload} | {memory} |".format(
                backend=result["backend"],
                tti=_milliseconds(result, "time_to_interactive")
                + _timing_change(result, previous, "time_to_interactive"),
                warm=_milliseconds(result, "warm_execute") + _timing_change(result, previous, "warm_execute"),
                tool=_milliseconds(result, "host_tool_round_trip")
                + _timing_change(result, previous, "host_tool_round_trip"),
                payload=_milliseconds(result, "one_megabyte_variable")
                + _timing_change(result, previous, "one_megabyte_variable"),
                memory=_mebibytes(memory),
            )
        )
    lines.extend([
        "",
        "TTI covers construction through the first completed execution. Raw samples, p95 values, host process-tree "
        "RSS, and environment metadata are in the uploaded `interpreter-benchmark-report` artifact.",
    ])
    if failures:
        lines.extend(["", "### Failures", "", *failures])
    return "\n".join(lines) + "\n"


__all__ = ["render_benchmark_summary"]
