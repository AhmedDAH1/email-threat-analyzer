# analyzer/core/scorer.py

from analyzer.core.models import ThreatIndicator, ScanResult


# Score thresholds → threat level
THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "CLEAN"),
]

# Per-category weight multipliers
# Some categories are inherently more reliable signals than others
CATEGORY_WEIGHTS = {
    "attachment": 1.4,
    "header":     1.2,
    "url":        1.1,
    "content":    0.8,
}


def _compute_score(indicators: list[ThreatIndicator]) -> int:
    """
    Compute a 0–100 threat score from a list of indicators.

    Strategy:
        - The single highest-severity indicator anchors the score
          (a strong individual signal should not be diluted by absence
           of others).
        - Additional indicators add diminishing extra points
          (so 5 weak indicators don't outweigh 1 critical one,
           but multiple corroborating signals do raise confidence).

    Each indicator contributes:
        severity * 10 * category_weight   (severity 0–10 → ~0–14 points)
    """
    if not indicators:
        return 0

    weighted = [
        i.severity * 10 * CATEGORY_WEIGHTS.get(i.category, 1.0)
        for i in indicators
    ]
    weighted.sort(reverse=True)

    # Anchor: the strongest single signal carries full weight.
    score = weighted[0]

    # Each additional indicator contributes at decreasing weight.
    # Second indicator at 50%, third at 25%, fourth at 12.5%, etc.
    for i, w in enumerate(weighted[1:], start=1):
        score += w * (0.5 ** i)

    return min(int(score), 100)


def _compute_level(score: int) -> str:
    """Map numeric score to a threat level label."""
    for threshold, level in THRESHOLDS:
        if score >= threshold:
            return level
    return "CLEAN"


def score_result(result: ScanResult) -> ScanResult:
    """
    Compute and attach threat_score and threat_level to a ScanResult.
    Mutates and returns the same object.
    """
    result.threat_score = _compute_score(result.indicators)
    result.threat_level = _compute_level(result.threat_score)
    return result