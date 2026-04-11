# tests/test_scorer.py

from analyzer.core.models import ThreatIndicator, ScanResult, EmailMessage
from analyzer.core.scorer import score_result


def make_email():
    """Minimal EmailMessage for testing."""
    return EmailMessage(
        subject="Test",
        sender="test@test.com",
        reply_to=None,
        recipients=["victim@example.com"],
        date=None,
        headers={},
        body_text=None,
        body_html=None,
        urls=[],
        attachments=[],
        raw=""
    )


def make_indicator(category="attachment", severity=5):
    return ThreatIndicator(
        category=category,
        name="test_indicator",
        description="Test",
        severity=severity,
        evidence="test"
    )


def test_no_indicators_gives_clean():
    result = ScanResult(email=make_email(), indicators=[])
    result = score_result(result)
    assert result.threat_score == 0
    assert result.threat_level == "CLEAN"


def test_single_low_severity_gives_low():
    result = ScanResult(email=make_email(), indicators=[
        make_indicator(category="content", severity=2)
    ])
    result = score_result(result)
    assert result.threat_level in ("CLEAN", "LOW")


def test_high_severity_attachment_raises_score():
    result = ScanResult(email=make_email(), indicators=[
        make_indicator(category="attachment", severity=9),
        make_indicator(category="attachment", severity=8),
    ])
    result = score_result(result)
    assert result.threat_score > 20
    assert result.threat_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_score_capped_at_100():
    indicators = [make_indicator(category="attachment", severity=10) for _ in range(20)]
    result = ScanResult(email=make_email(), indicators=indicators)
    result = score_result(result)
    assert result.threat_score <= 100


def test_category_weights_affect_score():
    """Attachment indicators should score higher than content indicators at same severity."""
    attachment_result = ScanResult(email=make_email(), indicators=[
        make_indicator(category="attachment", severity=5)
    ])
    content_result = ScanResult(email=make_email(), indicators=[
        make_indicator(category="content", severity=5)
    ])
    score_result(attachment_result)
    score_result(content_result)
    assert attachment_result.threat_score > content_result.threat_score


def test_critical_threshold():
    """Enough high-severity indicators should reach CRITICAL."""
    indicators = [make_indicator(category="attachment", severity=10) for _ in range(8)]
    result = ScanResult(email=make_email(), indicators=indicators)
    result = score_result(result)
    assert result.threat_level == "CRITICAL"