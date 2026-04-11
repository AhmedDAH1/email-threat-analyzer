# analyzer/core/virustotal.py

import hashlib
import time
import requests
from analyzer.core.models import ThreatIndicator

VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files"


def _get_headers(api_key: str) -> dict:
    return {"x-apikey": api_key}


def sha256_of_bytes(data: bytes) -> str:
    """Compute SHA256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def check_url(url: str, api_key: str) -> ThreatIndicator | None:
    """
    Submit a URL to VirusTotal and return a ThreatIndicator if flagged.
    Returns None if clean or if the request fails.
    """
    try:
        # VT requires URLs to be base64-encoded (url-safe, no padding)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"{VIRUSTOTAL_URL_ENDPOINT}/{url_id}",
            headers=_get_headers(api_key),
            timeout=10
        )

        if response.status_code == 404:
            # URL not in VT database — not necessarily clean, just unknown
            return None

        if response.status_code != 200:
            return None

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        if malicious > 0 or suspicious > 0:
            flagged = malicious + suspicious
            return ThreatIndicator(
                category="url",
                name="virustotal_url_hit",
                description=(
                    f"VirusTotal flagged this URL: "
                    f"{flagged}/{total} engines reported malicious or suspicious"
                ),
                severity=_severity_from_ratio(flagged, total),
                evidence=url
            )

    except Exception:
        # Never let VT errors crash the main analysis
        return None

    return None


def check_file_hash(data: bytes, filename: str, api_key: str) -> ThreatIndicator | None:
    """
    Look up a file's SHA256 hash on VirusTotal.
    Returns a ThreatIndicator if flagged, None if clean or unknown.
    """
    if not data:
        return None

    file_hash = sha256_of_bytes(data)

    try:
        response = requests.get(
            f"{VIRUSTOTAL_FILE_ENDPOINT}/{file_hash}",
            headers=_get_headers(api_key),
            timeout=10
        )

        if response.status_code == 404:
            # Hash not in VT database — file has never been seen before
            return None

        if response.status_code != 200:
            return None

        data_json = response.json()
        stats = data_json["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        if malicious > 0 or suspicious > 0:
            flagged = malicious + suspicious
            return ThreatIndicator(
                category="attachment",
                name="virustotal_hash_hit",
                description=(
                    f"VirusTotal flagged '{filename}': "
                    f"{flagged}/{total} engines reported malicious or suspicious"
                ),
                severity=_severity_from_ratio(flagged, total),
                evidence=f"SHA256: {file_hash}"
            )

    except Exception:
        return None

    return None


def _severity_from_ratio(flagged: int, total: int) -> int:
    """
    Map the ratio of flagged engines to a severity score 1–10.
    """
    if total == 0:
        return 5
    ratio = flagged / total
    if ratio >= 0.5:
        return 10
    elif ratio >= 0.2:
        return 8
    elif ratio >= 0.05:
        return 6
    else:
        return 4