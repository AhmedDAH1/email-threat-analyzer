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

    Formula per indicator:
        contribution = severity * category_weight
    
    Then we scale the total into 0–100 using a soft cap.
    """
    if not indicators:
        return 0

    raw = 0.0
    for indicator in indicators:
        weight = CATEGORY_WEIGHTS.get(indicator.category, 1.0)
        raw += indicator.severity * weight

    # A single critical attachment indicator (severity 10 * weight 1.4) = 14 points raw.
    # We treat 100 raw points as the ceiling → maps to score 100.
    # This gives room for realistic multi-indicator emails without instant maxing out.
    score = int((raw / 100) * 100)
    return min(score, 100)


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