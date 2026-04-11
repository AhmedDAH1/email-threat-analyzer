# analyzer/analyzers/content_analyzer.py

import re
from analyzer.core.models import EmailMessage, ThreatIndicator

URGENCY_PATTERNS = [
    r"act (now|immediately|urgently)",
    r"within \d+ hours?",
    r"account (will be|has been) (suspended|terminated|closed|locked)",
    r"immediate(ly)? (action|response|attention) required",
    r"failure to (respond|verify|confirm)",
    r"last (warning|chance|notice)",
    r"your account (is|has been) (compromised|suspended|locked)",
]

CREDENTIAL_PATTERNS = [
    r"(enter|confirm|verify|provide|update).{0,30}(password|passwd)",
    r"(enter|confirm|verify|provide|update).{0,30}(social security|ssn)",
    r"(enter|confirm|verify|provide|update).{0,30}(credit card|card number)",
    r"(enter|confirm|verify|provide|update).{0,30}(bank account|routing number)",
    r"(enter|confirm|verify|provide|update).{0,30}(date of birth|dob)",
]


def _check_urgency(text: str) -> list[ThreatIndicator]:
    """Detect urgency/panic language in email body."""
    indicators = []
    text_lower = text.lower()

    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="content",
                name="urgency_language",
                description="Email uses urgency or fear tactics to pressure the recipient",
                severity=4,
                evidence=match.group(0)
            ))
            break  # One urgency indicator per email is enough

    return indicators


def _check_credentials(text: str) -> list[ThreatIndicator]:
    """Detect requests for sensitive credentials in email body."""
    indicators = []
    text_lower = text.lower()

    for pattern in CREDENTIAL_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="content",
                name="credential_harvesting",
                description="Email requests sensitive credentials — legitimate services never do this",
                severity=8,
                evidence=match.group(0)
            ))
            break  # One credential indicator per email is enough

    return indicators


def _check_html_link_mismatch(html: str) -> list[ThreatIndicator]:
    """
    Detect links where display text shows a trusted domain
    but href points elsewhere.
    Example: <a href="http://evil.com">www.paypal.com</a>
    """
    indicators = []
    pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    matches = re.findall(pattern, html, re.IGNORECASE)

    for href, display_text in matches:
        display_clean = display_text.strip().lower()
        href_lower = href.lower()

        # Check if display text looks like a URL/domain
        if re.match(r'https?://', display_clean) or re.match(r'www\.', display_clean):
            # Extract root domain from display text
            display_domain = re.sub(r'https?://', '', display_clean).split('/')[0]
            # Check if display domain appears in href
            if display_domain and display_domain not in href_lower:
                indicators.append(ThreatIndicator(
                    category="content",
                    name="html_link_mismatch",
                    description=(
                        f"Link displays '{display_text.strip()}' "
                        f"but points to '{href}'"
                    ),
                    severity=9,
                    evidence=f"display='{display_text.strip()}' href='{href}'"
                ))

    return indicators


def analyze_content(email: EmailMessage) -> list[ThreatIndicator]:
    """Run all content-based analysis on email body."""
    indicators = []

    body = email.body_text or ""
    html = email.body_html or ""

    indicators += _check_urgency(body + " " + html)
    indicators += _check_credentials(body + " " + html)
    indicators += _check_html_link_mismatch(html)

    return indicators