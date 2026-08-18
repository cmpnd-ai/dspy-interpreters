from __future__ import annotations

import argparse
import json
from pathlib import Path

from dspy_interpreters.benchmark_summary import render_benchmark_summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--previous-report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    previous_payload = (
        json.loads(args.previous_report.read_text(encoding="utf-8")) if args.previous_report else None
    )
    summary = render_benchmark_summary(
        json.loads(args.report.read_text(encoding="utf-8")), previous_payload
    )
    if args.output is None:
        print(summary, end="")
    else:
        args.output.write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()
