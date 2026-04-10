from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class EmailMessage:
    """Structured representation of a parsed .eml file."""
    subject: str
    sender: str
    reply_to: Optional[str]
    recipients: list[str]
    date: Optional[str]
    headers: dict[str, str]        # All raw headers, keyed by name
    body_text: Optional[str]       # Plain text part
    body_html: Optional[str]       # HTML part (if present)
    urls: list[str]                # Extracted from body
    attachments: list[dict]        # Each: {filename, content_type, size, data}
    raw: str                       # The original raw .eml content


@dataclass
class ThreatIndicator:
    """A single suspicious finding produced by an analyzer."""
    category: str        # e.g. "header", "url", "attachment", "content"
    name: str            # e.g. "spoofed_sender", "suspicious_url"
    description: str     # Human-readable explanation
    severity: int        # 1 (low) to 10 (critical)
    evidence: str        # The raw value that triggered this indicator


@dataclass
class ScanResult:
    """The complete output of a full email scan."""
    email: EmailMessage
    indicators: list[ThreatIndicator] = field(default_factory=list)
    threat_score: int = 0                        # 0–100, computed by scoring.py
    threat_level: str = "CLEAN"                  # CLEAN / LOW / MEDIUM / HIGH / CRITICAL
    scanned_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )