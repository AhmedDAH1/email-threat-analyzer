import re
from email import message_from_string
from email.header import decode_header as _decode_header
from typing import Optional

from analyzer.core.models import EmailMessage


def decode_header(value: Optional[str]) -> str:
    """Decode encoded email headers (e.g. base64 UTF-8) to plain string."""
    if not value:
        return ""
    parts = _decode_header(value)
    decoded = []
    for part, encoding in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(encoding or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def extract_urls(text: Optional[str]) -> list[str]:
    """Extract all URLs from a string using regex."""
    if not text:
        return []
    pattern = r'https?://[^\s<>"\'()]+'
    return re.findall(pattern, text)


def parse_attachments(msg) -> list[dict]:
    """Walk the email tree and collect all attachments."""
    attachments = []
    for part in msg.walk():
        disposition = part.get("Content-Disposition", "")
        if "attachment" in disposition:
            attachments.append({
                "filename": part.get_filename() or "unknown",
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b""),
                "data": part.get_payload(decode=True),  # raw bytes
            })
    return attachments


def parse_email(raw: str) -> EmailMessage:
    """
    Parse a raw .eml string into a structured EmailMessage.
    This is the single entry point for all email ingestion.
    """
    msg = message_from_string(raw)

    # Extract plain text and HTML parts
    body_text = None
    body_html = None

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = part.get("Content-Disposition", "")

        if "attachment" in disposition:
            continue  # handled separately

        if content_type == "text/plain" and body_text is None:
            payload = part.get_payload(decode=True)
            if payload:
                body_text = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )

        elif content_type == "text/html" and body_html is None:
            payload = part.get_payload(decode=True)
            if payload:
                body_html = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )

    # Extract URLs from both body parts
    urls = list(set(extract_urls(body_text) + extract_urls(body_html)))

    # Collect all headers as a flat dict
    headers = dict(msg.items())

    return EmailMessage(
        subject=decode_header(msg.get("Subject")),
        sender=decode_header(msg.get("From")),
        reply_to=decode_header(msg.get("Reply-To")) or None,
        recipients=[decode_header(r) for r in msg.get_all("To", [])],
        date=msg.get("Date"),
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=parse_attachments(msg),
        raw=raw,
    )