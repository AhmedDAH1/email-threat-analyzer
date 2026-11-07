# analyzer/reporters/soar_forwarder.py
"""
Send a verdict to SOAR-Lite (https://github.com/AhmedDAH1/soar-lite), where it
becomes an incident: the URLs, domains and hashes are extracted as IOCs and
enriched, playbooks run, and an analyst works the case.

SOAR-Lite only accepts signed webhooks. Each request carries:
    X-Webhook-Timestamp: <unix time>
    X-Webhook-Signature: sha256=<HMAC-SHA256 of "<timestamp>." + body, keyed with the shared secret>
The secret comes from SOAR_WEBHOOK_SECRET and must match WEBHOOK_SECRET on
the SOAR-Lite server.
"""

import hashlib
import hmac
import json
import time
from urllib.parse import urlparse

import requests

from analyzer.core.models import ScanResult

EMAIL_WEBHOOK_PATH = "/api/webhooks/email"
LEVELS = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
MAX_ITEMS = 20          # URLs and indicators per request
MAX_EVIDENCE = 300      # characters of evidence per indicator
TIMEOUT_SECONDS = 10


def sign(body: bytes, secret: str, timestamp: int) -> str:
    """The X-Webhook-Signature value SOAR-Lite expects for this body."""
    message = f"{timestamp}.".encode() + body
    return "sha256=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def should_forward(result: ScanResult, minimum: str) -> bool:
    return LEVELS.index(result.threat_level) >= LEVELS.index(minimum)


def verdict_payload(result: ScanResult) -> dict:
    """A verdict in SOAR-Lite's email gateway webhook format."""
    email = result.email
    names = ", ".join(ind.name for ind in result.indicators[:MAX_ITEMS]) or "none"
    return {
        "from": email.sender,
        "subject": email.subject,
        "recipient": ", ".join(email.recipients),
        "verdict": "phishing" if result.threat_level in ("HIGH", "CRITICAL") else "suspicious",
        "severity": "low" if result.threat_level == "CLEAN" else result.threat_level.lower(),
        "description": (
            f"Threat score {result.threat_score}/100 ({result.threat_level}) from {email.sender}. "
            f"Indicators: {names}."
        ),
        "urls": email.urls[:MAX_ITEMS],
        "attachments": [a.get("filename") for a in email.attachments],
        "threat_score": result.threat_score,
        "indicators": [
            {
                "name": ind.name,
                "category": ind.category,
                "severity": ind.severity,
                "evidence": (ind.evidence or "")[:MAX_EVIDENCE],
            }
            for ind in result.indicators[:MAX_ITEMS]
        ],
        "detector": "email-threat-analyzer",
    }


def forward(result: ScanResult, base_url: str, secret: str) -> tuple[bool, str]:
    """Send the verdict. Returns (accepted, message); never raises on network errors."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Not an http(s) URL: {base_url!r} (example: http://localhost:8000)")
    if not secret:
        raise ValueError("Set SOAR_WEBHOOK_SECRET to the WEBHOOK_SECRET configured in SOAR-Lite")

    url = base_url.rstrip("/") + EMAIL_WEBHOOK_PATH
    body = json.dumps(verdict_payload(result)).encode()
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": str(timestamp),
        "X-Webhook-Signature": sign(body, secret, timestamp),
    }
    try:
        response = requests.post(url, data=body, headers=headers, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as e:
        return False, f"could not reach SOAR-Lite at {url} ({e.__class__.__name__})"
    if response.status_code != 201:
        return False, f"SOAR-Lite refused the verdict: HTTP {response.status_code} {response.text[:200]}"
    return True, f"sent to SOAR-Lite as incident #{response.json().get('incident_id')}"
