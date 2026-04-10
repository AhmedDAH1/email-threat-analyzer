import pytest
from analyzer.core.parser import parse_email
from analyzer.core.models import EmailMessage


# --- Sample .eml strings ---

SIMPLE_EMAIL = """From: attacker@evil.com
To: victim@company.com
Subject: Urgent: Verify your account
Date: Mon, 10 Apr 2024 10:00:00 +0000
Reply-To: harvest@phish.net

Please click here to verify: http://paypa1.com/login
Your account will be suspended otherwise.
"""

MULTIPART_EMAIL = """From: sender@example.com
To: user@example.com
Subject: Hello
Date: Mon, 10 Apr 2024 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

This is the plain text body. Visit http://example.com for info.

--boundary123
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 7bit

<html><body><a href="http://example.com">Click here</a></body></html>

--boundary123
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKdGVzdA==

--boundary123--
"""


# --- Tests ---

class TestParseSimpleEmail:

    def test_returns_email_message_instance(self):
        result = parse_email(SIMPLE_EMAIL)
        assert isinstance(result, EmailMessage)

    def test_subject_decoded(self):
        result = parse_email(SIMPLE_EMAIL)
        assert result.subject == "Urgent: Verify your account"

    def test_sender_parsed(self):
        result = parse_email(SIMPLE_EMAIL)
        assert result.sender == "attacker@evil.com"

    def test_reply_to_parsed(self):
        result = parse_email(SIMPLE_EMAIL)
        assert result.reply_to == "harvest@phish.net"

    def test_urls_extracted(self):
        result = parse_email(SIMPLE_EMAIL)
        assert "http://paypa1.com/login" in result.urls

    def test_raw_preserved(self):
        result = parse_email(SIMPLE_EMAIL)
        assert result.raw == SIMPLE_EMAIL


class TestParseMultipartEmail:

    def test_body_text_extracted(self):
        result = parse_email(MULTIPART_EMAIL)
        assert result.body_text is not None
        assert "plain text body" in result.body_text

    def test_body_html_extracted(self):
        result = parse_email(MULTIPART_EMAIL)
        assert result.body_html is not None
        assert "<html>" in result.body_html

    def test_attachment_captured(self):
        result = parse_email(MULTIPART_EMAIL)
        assert len(result.attachments) == 1
        assert result.attachments[0]["filename"] == "invoice.pdf"
        assert result.attachments[0]["content_type"] == "application/pdf"

    def test_attachment_not_in_body(self):
        result = parse_email(MULTIPART_EMAIL)
        # PDF content should not leak into body_text
        assert "JVBERi0" not in (result.body_text or "")

    def test_urls_deduplicated(self):
        result = parse_email(MULTIPART_EMAIL)
        # http://example.com appears in both plain and HTML — should appear once
        url_count = result.urls.count("http://example.com")
        assert url_count == 1