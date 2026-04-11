# analyzer/reporters/json_reporter.py

import json
from analyzer.core.models import ScanResult


def render(result: ScanResult) -> str:
    """Serialize a ScanResult to a formatted JSON string."""
    output = {
        "scanned_at": result.scanned_at,
        "threat_score": result.threat_score,
        "threat_level": result.threat_level,
        "email": {
            "subject": result.email.subject,
            "sender": result.email.sender,
            "reply_to": result.email.reply_to,
            "recipients": result.email.recipients,
            "date": result.email.date,
            "urls": result.email.urls,
            "attachments": [
                {
                    "filename": a.get("filename"),
                    "content_type": a.get("content_type"),
                    "size": a.get("size"),
                }
                for a in result.email.attachments
            ],
        },
        "indicators": [
            {
                "category": ind.category,
                "name": ind.name,
                "description": ind.description,
                "severity": ind.severity,
                "evidence": ind.evidence,
            }
            for ind in result.indicators
        ],
    }
    return json.dumps(output, indent=2)


def save(result: ScanResult, path: str) -> None:
    """Write JSON report to a file."""
    with open(path, "w") as f:
        f.write(render(result))