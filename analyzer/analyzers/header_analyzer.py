import re
from analyzer.core.models import EmailMessage, ThreatIndicator

# Brands commonly impersonated in phishing emails
KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "bank", "secure",
    "verify", "account", "update", "alert"
]


def extract_domain(address: str) -> str:
    """Extract domain from an email address string."""
    match = re.search(r'@([\w\.-]+)', address)
    return match.group(1).lower() if match else ""


def analyze_headers(email: EmailMessage) -> list[ThreatIndicator]:
    """
    Analyze email headers for phishing indicators.
    Returns a list of ThreatIndicator objects.
    """
    indicators = []

    # --- Check 1: Display name spoofing ---
    sender = email.sender.lower()
    sender_domain = extract_domain(sender)

    # Extract display name (everything before the < )
    display_name_match = re.match(r'^([^<]+)<', sender)
    display_name = display_name_match.group(1).strip().lower() if display_name_match else ""

    for brand in KNOWN_BRANDS:
        if brand in display_name and brand not in sender_domain:
            indicators.append(ThreatIndicator(
                category="header",
                name="display_name_spoofing",
                description=f"Display name contains '{brand}' but sending domain is '{sender_domain}'",
                severity=7,
                evidence=email.sender,
            ))
            break  # One indicator per email is enough for this check

    # --- Check 2: Reply-To mismatch ---
    if email.reply_to:
        from_domain = extract_domain(email.sender)
        reply_domain = extract_domain(email.reply_to)

        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(ThreatIndicator(
                category="header",
                name="reply_to_mismatch",
                description=f"From domain '{from_domain}' doesn't match Reply-To domain '{reply_domain}'",
                severity=6,
                evidence=f"From: {email.sender} | Reply-To: {email.reply_to}",
            ))

    # --- Check 3: Authentication failures ---
    auth_results = email.headers.get("Authentication-Results", "").lower()

    if auth_results:
        failures = []
        for check in ["spf", "dkim", "dmarc"]:
            pattern = rf'{check}=(\w+)'
            match = re.search(pattern, auth_results)
            if match and match.group(1) in ("fail", "none", "neutral", "permerror"):
                failures.append(f"{check.upper()}={match.group(1)}")

        if failures:
            indicators.append(ThreatIndicator(
                category="header",
                name="authentication_failure",
                description=f"Email failed authentication checks: {', '.join(failures)}",
                severity=5 if len(failures) == 1 else 8,
                evidence=auth_results[:200],  # truncate — can be very long
            ))

    return indicators