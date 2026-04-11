# analyzer/analyzers/content_analyzer.py

from analyzer.core.models import EmailMessage, ThreatIndicator


def analyze_content(email: EmailMessage) -> list[ThreatIndicator]:
    """Placeholder — content analysis not yet implemented."""
    return []