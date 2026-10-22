from __future__ import annotations

from pathlib import Path

from ..core.models import ScanResult


def render(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def write(result: ScanResult, path: Path) -> Path:
    path.write_text(render(result), encoding="utf-8")
    return path