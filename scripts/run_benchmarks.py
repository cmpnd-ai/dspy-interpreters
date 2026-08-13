from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dspy

from dspy_interpreters import LocalInterpreter
from dspy_interpreters.benchmarks import benchmark_interpreter

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cold-runs", type=int, default=1)
    parser.add_argument("--warm-runs", type=int, default=20)
    parser.add_argument("--modal", action="store_true")
    parser.add_argument("--exe", action="store_true")
    parser.add_argument("--strict", action="store_true", help="exit nonzero when any selected backend fails")
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "benchmarks-latest.json")
    args = parser.parse_args()

    factories: list[tuple[str, Any]] = [("Local / in-process", LocalInterpreter)]
    unavailable = []
    try:
        from dspy_interpreters.monty import MontyInterpreter
    except ImportError as exc:
        unavailable.append({"backend": "Monty", "status": "failed", "error": f"ImportError: {exc}"})
    else:
        factories.append(("Monty", MontyInterpreter))
    factories.append(("DSPy Deno/Pyodide", dspy.PythonInterpreter))
    try:
        from dspy_interpreters.ikernel import IPythonInterpreter
    except ImportError as exc:
        unavailable.append(
            {"backend": "IPython kernel subprocess", "status": "failed", "error": f"ImportError: {exc}"}
        )
    else:
        factories.append(("IPython kernel subprocess", IPythonInterpreter))
    if args.modal:
        from dspy_interpreters.modal import ModalInterpreter

        factories.append(("Modal remote", ModalInterpreter))
    if args.exe:
        from dspy_interpreters.exe import ExeDevInterpreter

        factories.append(("exe.dev remote", ExeDevInterpreter))

    results = unavailable if args.strict else []
    for name, factory in factories:
        print(f"benchmarking {name}", flush=True)
        try:
            report = benchmark_interpreter(
                factory, name=name, cold_runs=args.cold_runs, warm_runs=args.warm_runs
            )
        except Exception as exc:
            results.append({"backend": name, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        else:
            results.append(report.to_dict())
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    if args.strict and any(result.get("status") == "failed" for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
