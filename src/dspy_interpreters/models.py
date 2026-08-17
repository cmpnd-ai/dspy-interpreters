from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    id: str
    passed: bool
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ConformanceReport:
    results: tuple[CheckResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def failed_ids(self) -> tuple[str, ...]:
        return tuple(result.id for result in self.results if not result.passed)

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "results": [result.to_dict() for result in self.results]}

    def raise_for_failures(self) -> None:
        if not self.passed:
            details = "; ".join(f"{result.id}: {result.detail}" for result in self.results if not result.passed)
            raise AssertionError(f"Interpreter conformance failed: {details}")

    def to_json(self, path: str | Path | None = None) -> str:
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True)
        if path is not None:
            Path(path).write_text(payload + "\n", encoding="utf-8")
        return payload
