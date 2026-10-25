from __future__ import annotations


def calibrate(base: float, verifications: int = 0, indicators: int = 1,
              canary_verified: bool = False, timing_verified: bool = False) -> float:
    """Calibrate confidence score based on evidence.

    base: starting confidence (0.0-1.0)
    verifications: number of independent verifications passed
    indicators: number of independent indicators found
    canary_verified: whether canary re-check passed
    timing_verified: whether timing was verified
    """
    score = base
    if canary_verified:
        score += 0.1
    if timing_verified:
        score += 0.05
    score += min(0.15, verifications * 0.05)
    score += min(0.1, (indicators - 1) * 0.05)
    return min(1.0, max(0.1, round(score, 2)))