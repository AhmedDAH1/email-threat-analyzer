"""The web API: analysis results, including the verdict in SOAR-Lite's format."""

import unittest
from pathlib import Path

from web_app import app

SAMPLE = (Path(__file__).resolve().parent.parent / "samples" / "phishing_test.eml").read_text()


class WebApiTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_analysis_includes_the_soar_verdict(self):
        response = self.client.post("/api/analyze", json={"raw": SAMPLE})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertGreaterEqual(data["threat_score"], 70)
        soar = data["soar"]
        self.assertEqual(soar["verdict"], "phishing")
        self.assertIn("paypa1", soar["from"])
        self.assertTrue(soar["urls"])                 # becomes IOCs in SOAR-Lite

    def test_empty_and_oversized_emails_are_refused(self):
        self.assertEqual(self.client.post("/api/analyze", json={"raw": "  "}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", json={"raw": "x" * 1_000_001}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
