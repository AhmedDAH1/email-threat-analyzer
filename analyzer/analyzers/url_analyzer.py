import re
from urllib.parse import urlparse
from analyzer.core.models import EmailMessage, ThreatIndicator

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".cc", ".su", ".buzz", ".live", ".online"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd"
}

KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "bankofamerica", "wellsfargo"
]


def extract_domain(url: str) -> str:
    """Extract the netloc (domain + subdomains) from a URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def get_root_domain(netloc: str) -> str:
    """
    Extract the root domain from a netloc string.
    e.g. 'paypal.com.evil.com' -> 'evil.com'
    """
    parts = netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc


def analyze_urls(email: EmailMessage) -> list[ThreatIndicator]:
    """
    Analyze URLs extracted from the email body.
    Returns a list of ThreatIndicator objects.
    """
    indicators = []

    for url in email.urls:
        netloc = extract_domain(url)
        if not netloc:
            continue

        root_domain = get_root_domain(netloc)

        # --- Check 1: Raw IP address URL ---
        ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$'
        if re.match(ip_pattern, netloc):
            indicators.append(ThreatIndicator(
                category="url",
                name="ip_address_url",
                description="URL uses a raw IP address instead of a domain name",
                severity=7,
                evidence=url,
            ))
            continue  # No need to run further checks on this URL

        # --- Check 2: URL shortener ---
        if root_domain in URL_SHORTENERS:
            indicators.append(ThreatIndicator(
                category="url",
                name="url_shortener",
                description=f"URL uses a shortener service that hides the real destination",
                severity=5,
                evidence=url,
            ))
            continue

        # --- Check 3: Suspicious TLD ---
        tld = "." + root_domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            indicators.append(ThreatIndicator(
                category="url",
                name="suspicious_tld",
                description=f"URL uses a TLD commonly associated with phishing: '{tld}'",
                severity=4,
                evidence=url,
            ))

        # --- Check 4: Misleading subdomain ---
        for brand in KNOWN_BRANDS:
            if brand in netloc and brand not in root_domain:
                indicators.append(ThreatIndicator(
                    category="url",
                    name="misleading_subdomain",
                    description=f"Brand '{brand}' appears in subdomain but not in root domain '{root_domain}'",
                    severity=8,
                    evidence=url,
                ))
                break

        # --- Check 5: Lookalike domain (typosquatting) ---
        for brand in KNOWN_BRANDS:
            if brand in root_domain:
                continue  # Legitimate match, skip
            # Check for character substitutions: 0→o, 1→i/l, 3→e
            normalized = root_domain.replace("0", "o").replace("1", "i").replace("3", "e")
            if brand in normalized:
                indicators.append(ThreatIndicator(
                    category="url",
                    name="lookalike_domain",
                    description=f"Domain '{root_domain}' may be impersonating '{brand}' via character substitution",
                    severity=8,
                    evidence=url,
                ))
                break

    return indicators