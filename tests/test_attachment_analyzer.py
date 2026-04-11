from analyzer.core.models import EmailMessage
from analyzer.analyzers.attachment_analyzer import analyze_attachments

def make_email(attachments):
    """Helper to build a minimal EmailMessage with custom attachments."""
    return EmailMessage(
        subject="Test",
        sender="test@example.com",
        reply_to=None,
        recipients=["victim@example.com"],
        date=None,
        headers={},
        body_text=None,
        body_html=None,
        urls=[],
        attachments=attachments,
        raw=""
    )


def test_dangerous_extension():
    email = make_email([
        {"filename": "malware.exe", "content_type": "application/octet-stream", "size": 1000, "data": b""}
    ])
    indicators = analyze_attachments(email)
    names = [i.name for i in indicators]
    assert "dangerous_extension" in names


def test_double_extension():
    email = make_email([
        {"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size": 1000, "data": b""}
    ])
    indicators = analyze_attachments(email)
    names = [i.name for i in indicators]
    assert "double_extension" in names


def test_content_type_mismatch():
    email = make_email([
        {"filename": "document.pdf", "content_type": "application/octet-stream", "size": 500, "data": b""}
    ])
    indicators = analyze_attachments(email)
    names = [i.name for i in indicators]
    assert "content_type_mismatch" in names


def test_suspicious_archive():
    email = make_email([
        {"filename": "files.zip", "content_type": "application/zip", "size": 2000, "data": b""}
    ])
    indicators = analyze_attachments(email)
    names = [i.name for i in indicators]
    assert "suspicious_archive" in names


def test_clean_attachment():
    email = make_email([
        {"filename": "photo.png", "content_type": "image/png", "size": 300, "data": b""}
    ])
    indicators = analyze_attachments(email)
    assert indicators == []