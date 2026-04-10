from analyzer.analyzers.url_analyzer import analyze_urls
from analyzer.core.models import EmailMessage

def make_email(urls):
    return EmailMessage(
        subject="", sender="", reply_to=None,
        recipients=[], date=None, headers={},
        body_text=None, body_html=None,
        urls=urls, attachments=[], raw=""
    )

def test_clean_url_no_indicators():
    email = make_email(["https://www.google.com/search"])
    result = analyze_urls(email)
    assert result == []

def test_ip_address_url():
    email = make_email(["http://192.168.1.1/login"])
    result = analyze_urls(email)
    assert len(result) == 1
    assert result[0].name == "ip_address_url"

def test_url_shortener():
    email = make_email(["http://bit.ly/abc123"])
    result = analyze_urls(email)
    assert len(result) == 1
    assert result[0].name == "url_shortener"

def test_misleading_subdomain():
    email = make_email(["http://paypal.com.evil.com/login"])
    result = analyze_urls(email)
    assert len(result) == 1
    assert result[0].name == "misleading_subdomain"