from __future__ import annotations

import difflib


def fuzzy_similarity(a: str, b: str) -> float:
    """Return similarity ratio between two strings (0.0 to 1.0)."""
    if a is None:
        a = ""
    if b is None:
        b = ""
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def is_similar(a: str, b: str, threshold: float = 0.95) -> bool:
    """Check if two responses are similar (likely same page)."""
    return fuzzy_similarity(a, b) >= threshold


def response_diff_magnitude(baseline: str, response: str) -> float:
    """Return how different two responses are (0.0 = identical, 1.0 = completely different)."""
    return 1.0 - fuzzy_similarity(baseline, response)