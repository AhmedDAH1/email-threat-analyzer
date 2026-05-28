# analyzer/engine.py
"""
Shared analysis engine.

Provides analyze_raw() — runs the full analyzer pipeline on a raw .eml
string with no disk I/O. Used by both the CLI (main.py) and the web app
(web_app.py) so the scoring/parsing logic lives in exactly one place.
"""

from analyzer.core.parser import parse_email
from analyzer.core.models import ScanResult
from analyzer.core.scorer import score_result
from analyzer.analyzers.header_analyzer import analyze_headers
from analyzer.analyzers.url_analyzer import analyze_urls
from analyzer.analyzers.attachment_analyzer import analyze_attachments
from analyzer.analyzers.content_analyzer import analyze_content


def analyze_raw(raw: str, vt_api_key: str | None = None) -> ScanResult:
    """Run all analyzers on a raw .eml string and return a scored result."""
    email = parse_email(raw)

    indicators = []
    indicators += analyze_headers(email)
    indicators += analyze_urls(email, api_key=vt_api_key)
    indicators += analyze_attachments(email, api_key=vt_api_key)
    indicators += analyze_content(email)

    result = ScanResult(email=email, indicators=indicators)
    return score_result(result)


def analyze_file(eml_path: str, vt_api_key: str | None = None) -> ScanResult:
    """Read a .eml file from disk and analyze it."""
    with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return analyze_raw(raw, vt_api_key=vt_api_key)
