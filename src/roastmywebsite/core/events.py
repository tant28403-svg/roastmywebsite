from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable[[Any], None]]] = defaultdict(list)

    def on(self, event: str, callback: Callable[[Any], None]) -> None:
        self._listeners[event].append(callback)

    def emit(self, event: str, payload: Any = None) -> None:
        for callback in list(self._listeners[event]):
            try:
                callback(payload)
            except Exception:
                pass