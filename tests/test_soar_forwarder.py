# tests/test_soar_forwarder.py
"""Sending verdicts to SOAR-Lite: payload format, signature, and failure handling."""

import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from analyzer.engine import analyze_raw
from analyzer.reporters import soar_forwarder
from analyzer.reporters.soar_forwarder import forward, should_forward, sign, verdict_payload

SECRET = "shared-secret"
SAMPLE = (Path(__file__).resolve().parent.parent / "samples" / "phishing_test.eml").read_text()


class FakeSoarLite(BaseHTTPRequestHandler):
    received = []
    status = 201

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakeSoarLite.received.append((self.path, dict(self.headers), body))
        self.send_response(FakeSoarLite.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"incident_id": 7}).encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def soar_url():
    server = HTTPServer(("127.0.0.1", 0), FakeSoarLite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def reset_fake():
    FakeSoarLite.received = []
    FakeSoarLite.status = 201


@pytest.fixture(scope="module")
def phishing():
    return analyze_raw(SAMPLE)


def test_payload_matches_soar_lite_email_format(phishing):
    payload = verdict_payload(phishing)
    assert payload["subject"] == phishing.email.subject
    assert payload["from"] == phishing.email.sender
    assert payload["verdict"] == "phishing"
    assert payload["severity"] == phishing.threat_level.lower()
    assert str(phishing.threat_score) in payload["description"]
    assert payload["urls"] == phishing.email.urls[:20]   # SOAR-Lite extracts these as IOCs


def test_payload_is_bounded(phishing):
    payload = verdict_payload(phishing)
    assert len(payload["indicators"]) <= soar_forwarder.MAX_ITEMS
    assert all(len(i["evidence"]) <= soar_forwarder.MAX_EVIDENCE for i in payload["indicators"])


def test_signature_matches_soar_lite_scheme():
    body, ts = b'{"a": 1}', 1700000000
    expected = hmac.new(SECRET.encode(), b"1700000000." + body, hashlib.sha256).hexdigest()
    assert sign(body, SECRET, ts) == "sha256=" + expected


@pytest.mark.parametrize(("level", "minimum", "expected"), [
    ("CRITICAL", "MEDIUM", True),
    ("MEDIUM", "MEDIUM", True),
    ("LOW", "MEDIUM", False),
    ("CLEAN", "LOW", False),
])
def test_only_verdicts_at_or_above_the_minimum_are_forwarded(phishing, level, minimum, expected):
    phishing_copy = type(phishing)(email=phishing.email, threat_level=level)
    assert should_forward(phishing_copy, minimum) is expected


def test_sends_a_signed_request(phishing, soar_url):
    ok, message = forward(phishing, soar_url, SECRET)
    assert ok and "#7" in message
    path, headers, body = FakeSoarLite.received[0]
    assert path == "/api/webhooks/email"
    ts = int(headers["X-Webhook-Timestamp"])
    assert abs(time.time() - ts) < 5
    assert headers["X-Webhook-Signature"] == sign(body, SECRET, ts)


def test_refusal_is_reported(phishing, soar_url):
    FakeSoarLite.status = 401
    ok, message = forward(phishing, soar_url, SECRET)
    assert not ok and "401" in message


def test_unreachable_soar_lite_is_reported_not_raised(phishing):
    ok, message = forward(phishing, "http://127.0.0.1:9", SECRET)
    assert not ok and "could not reach" in message


@pytest.mark.parametrize("url", ["ftp://host", "localhost:8000", "file:///etc/passwd"])
def test_only_http_urls(phishing, url):
    with pytest.raises(ValueError):
        forward(phishing, url, SECRET)


def test_secret_is_required(phishing, soar_url):
    with pytest.raises(ValueError):
        forward(phishing, soar_url, "")
