from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dspy

from dspy_interpreters import (
    LocalInterpreter,
    ModalInterpreter,
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def run(name: str, factory: Any) -> dict[str, Any]:
    suites = {}
    for suite in (check_interpreter, check_bind, check_execution_instructions, check_rlm, check_flex_facade):
        report = suite(factory)
        suites[suite.__name__] = report.to_dict()
    return {"name": name, "suites": suites}


def unavailable(name: str, reason: str) -> dict[str, Any]:
    return {"name": name, "suites": {}, "status": "blocked", "reason": reason}


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    implementations = [run("Local / in-process", LocalInterpreter)]

    try:
        from dspy_interpreters.monty import MontyInterpreter
    except ImportError as exc:
        implementations.append(unavailable("Monty", str(exc)))
    else:
        implementations.append(run("Monty", MontyInterpreter))

    try:
        implementations.append(run("DSPy Deno/Pyodide reference", dspy.PythonInterpreter))
    except Exception as exc:
        implementations.append(unavailable("DSPy Deno/Pyodide reference", str(exc)))

    if "--modal" in sys.argv:
        implementations.append(run("Modal remote", ModalInterpreter))
    else:
        implementations.append(unavailable("Modal remote", "run with --modal to execute live provider checks"))

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_revision": os.popen("git rev-parse --short HEAD 2>/dev/null").read().strip() or "uncommitted",
        "implementations": implementations,
    }
    (REPORTS / "latest.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(REPORTS / "latest.json")


if __name__ == "__main__":
    main()
