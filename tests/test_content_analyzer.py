# tests/test_content_analyzer.py

from analyzer.core.models import EmailMessage
from analyzer.analyzers.content_analyzer import analyze_content


def make_email(body_text="", body_html=""):
    return EmailMessage(
        subject="Test",
        sender="test@example.com",
        reply_to=None,
        recipients=["victim@example.com"],
        date=None,
        headers={},
        body_text=body_text,
        body_html=body_html,
        urls=[],
        attachments=[],
        raw=""
    )


def test_urgency_language_detected():
    email = make_email(body_text="Your account has been suspended. Act immediately.")
    indicators = analyze_content(email)
    names = [i.name for i in indicators]
    assert "urgency_language" in names


def test_urgency_within_hours():
    email = make_email(body_text="Please verify within 24 hours or your account will be closed.")
    indicators = analyze_content(email)
    names = [i.name for i in indicators]
    assert "urgency_language" in names


def test_credential_harvesting_password():
    email = make_email(body_text="Please confirm your password to continue.")
    indicators = analyze_content(email)
    names = [i.name for i in indicators]
    assert "credential_harvesting" in names


def test_credential_harvesting_credit_card():
    email = make_email(body_text="Enter your credit card number to verify your identity.")
    indicators = analyze_content(email)
    names = [i.name for i in indicators]
    assert "credential_harvesting" in names


def test_html_link_mismatch_detected():
    html = '<a href="http://evil.com/steal">www.paypal.com</a>'
    email = make_email(body_html=html)
    indicators = analyze_content(email)
    names = [i.name for i in indicators]
    assert "html_link_mismatch" in names


def test_html_link_mismatch_severity():
    html = '<a href="http://evil.com/steal">www.paypal.com</a>'
    email = make_email(body_html=html)
    indicators = analyze_content(email)
    mismatch = [i for i in indicators if i.name == "html_link_mismatch"]
    assert mismatch[0].severity == 9


def test_clean_email_no_indicators():
    email = make_email(
        body_text="Hi, please find your monthly newsletter attached. Have a great day!"
    )
    indicators = analyze_content(email)
    assert indicators == []


def test_only_one_urgency_indicator_per_email():
    email = make_email(
        body_text="Act immediately. Your account will be suspended within 24 hours. Last warning."
    )
    indicators = analyze_content(email)
    urgency = [i for i in indicators if i.name == "urgency_language"]
    assert len(urgency) == 1