# analyzer/analyzers/attachment_analyzer.py

import os
from analyzer.core.models import EmailMessage, ThreatIndicator
from analyzer.core import virustotal

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".docm", ".xlsm", ".pptm",
    ".hta", ".msi", ".dll", ".reg"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}

EXTENSION_CONTENT_TYPE_MAP = {
    ".pdf": "pdf",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".png": "png",
    ".gif": "gif",
    ".docx": "word",
    ".xlsx": "spreadsheet",
    ".txt": "text",
}


def get_extensions(filename: str) -> list[str]:
    parts = filename.lower().split(".")
    if len(parts) <= 1:
        return []
    return ["." + p for p in parts[1:]]


def analyze_attachments(email: EmailMessage, api_key: str | None = None) -> list[ThreatIndicator]:
    """
    Analyze email attachments for suspicious indicators.
    Pass api_key to enable VirusTotal hash lookups.
    """
    indicators = []

    for attachment in email.attachments:
        filename = attachment.get("filename", "unknown").lower()
        content_type = attachment.get("content_type", "").lower()
        size = attachment.get("size", 0)
        data: bytes = attachment.get("data") or b""
        extensions = get_extensions(filename)

        if not extensions:
            continue

        final_ext = extensions[-1]

        # --- Check 1: Dangerous extension ---
        if final_ext in DANGEROUS_EXTENSIONS:
            indicators.append(ThreatIndicator(
                category="attachment",
                name="dangerous_extension",
                description=f"Attachment has a potentially executable extension '{final_ext}'",
                severity=8,
                evidence=filename,
            ))

        # --- Check 2: Double extension trick ---
        if len(extensions) > 1 and final_ext in DANGEROUS_EXTENSIONS:
            indicators.append(ThreatIndicator(
                category="attachment",
                name="double_extension",
                description=f"Attachment uses double extension to disguise executable: '{filename}'",
                severity=9,
                evidence=filename,
            ))

        # --- Check 3: Extension/content-type mismatch ---
        expected_fragment = EXTENSION_CONTENT_TYPE_MAP.get(final_ext)
        if expected_fragment and expected_fragment not in content_type:
            indicators.append(ThreatIndicator(
                category="attachment",
                name="content_type_mismatch",
                description=f"Extension '{final_ext}' doesn't match content type '{content_type}'",
                severity=6,
                evidence=f"{filename} declared as {content_type}",
            ))

        # --- Check 4: Suspicious archive ---
        if final_ext in ARCHIVE_EXTENSIONS:
            indicators.append(ThreatIndicator(
                category="attachment",
                name="suspicious_archive",
                description="Attachment is a compressed archive which may conceal malicious files",
                severity=4,
                evidence=filename,
            ))

        # --- Check 5: VirusTotal hash lookup (optional) ---
        if api_key and data:
            vt_indicator = virustotal.check_file_hash(data, filename, api_key)
            if vt_indicator:
                indicators.append(vt_indicator)

    return indicators