from __future__ import annotations

import importlib.metadata
from typing import Any


def load_entry_point_plugins(group: str = "roastmywebsite.modules") -> dict[str, Any]:
    plugins: dict[str, Any] = {}
    try:
        eps = importlib.metadata.entry_points()
        selected = eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])
    except Exception:
        selected = []
    for ep in selected:
        try:
            plugins[ep.name] = ep.load()
        except Exception:
            continue
    return plugins