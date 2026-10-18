import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from threat_intel import (
    apply_threat_result,
    check_google_safe_browsing,
    match_local_feed,
)


class LocalThreatFeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "feed.json"

    def tearDown(self):
        self.temp.cleanup()

    def write_feed(self, updated_at, domains):
        self.path.write_text(json.dumps({
            "provider": "Test feed",
            "updated_at": updated_at,
            "domains": domains,
        }), encoding="utf-8")

    def test_exact_fresh_feed_match_is_reported_with_provenance(self):
        updated_at = datetime.now(timezone.utc).isoformat()
        self.write_feed(updated_at, ["bad.example"])
        result = match_local_feed("bad.example", str(self.path))
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["match"])
        self.assertEqual(result["provider"], "Test feed")

    def test_stale_feed_is_not_used_for_a_match(self):
        updated_at = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        self.write_feed(updated_at, ["bad.example"])
        result = match_local_feed("bad.example", str(self.path))
        self.assertEqual(result["status"], "stale")
        self.assertFalse(result["match"])

    def test_feed_match_overrides_local_result_with_cautious_warning(self):
        result = {
            "coverage": [{"check": "local_rules", "status": "completed"}],
            "evidence": [],
            "decision_reason": [],
            "recommended_actions": [],
        }
        updated_at = datetime.now(timezone.utc).isoformat()
        self.write_feed(updated_at, ["bad.example"])
        reputation = match_local_feed("bad.example", str(self.path))
        applied = apply_threat_result(result, reputation)
        self.assertEqual(applied["risk_label"], "known_malicious")
        self.assertEqual(applied["coverage"][1]["provider"], "Test feed")
        self.assertEqual(applied["score"], 100)

    def test_safe_browsing_is_not_contacted_without_an_api_key(self):
        with patch("threat_intel.urlopen") as open_url:
            result = check_google_safe_browsing("https://example.org/", "")
        self.assertEqual(result["status"], "not_configured")
        open_url.assert_not_called()

    def test_safe_browsing_no_match_marks_url_checked_but_not_safe(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"{}"
        api_key = "test key/+"
        with patch("threat_intel.urlopen", return_value=response) as open_url:
            reputation = check_google_safe_browsing("https://example.org/", api_key)
        request = open_url.call_args.args[0]
        self.assertEqual(parse_qs(urlsplit(request.full_url).query), {"key": [api_key]})
        self.assertIsNone(request.get_header("X-goog-api-key"))
        self.assertEqual(json.loads(request.data)["threatInfo"]["threatEntries"], [
            {"url": "https://example.org/"},
        ])
        self.assertEqual(reputation["status"], "completed")
        self.assertFalse(reputation["match"])
        result = apply_threat_result({
            "locale": "en",
            "risk_label": "unknown",
            "score": 0,
            "title": "Unable to determine",
            "coverage": [{"check": "local_rules", "status": "completed"}],
            "evidence": [],
            "decision_reason": [],
            "recommended_actions": [],
        }, {"status": "not_configured", "provider": None, "match": False}, reputation)
        self.assertEqual(result["risk_label"], "no_known_threat")
        self.assertIn("does not prove", result["evidence"][0]["text"])
        self.assertIn("miss unsafe sites", result["disclaimer"])
        self.assertEqual(result["coverage"][1]["status"], "completed")

    def test_safe_browsing_match_includes_google_advisory_attribution(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            "matches": [{"threatType": "SOCIAL_ENGINEERING"}],
        }).encode()
        with patch("threat_intel.urlopen", return_value=response):
            reputation = check_google_safe_browsing(
                "https://phishing.example/login", "test-key",
            )
        result = apply_threat_result({
            "locale": "en",
            "risk_label": "unknown",
            "score": 0,
            "title": "Unable to determine",
            "coverage": [{"check": "local_rules", "status": "completed"}],
            "evidence": [],
            "decision_reason": [],
            "recommended_actions": [],
        }, {"status": "not_configured", "provider": None, "match": False}, reputation)
        self.assertEqual(result["risk_label"], "known_malicious")
        self.assertEqual(result["title"], "Potentially unsafe match")
        self.assertEqual(result["attribution"]["text"], "Advisory provided by Google.")
        self.assertEqual(reputation["threat_types"], ["SOCIAL_ENGINEERING"])

    def test_safe_browsing_http_failures_are_sanitized_and_nonfatal(self):
        error = HTTPError(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            403, "key disabled", {}, None,
        )
        with patch("threat_intel.urlopen", side_effect=error):
            result = check_google_safe_browsing(
                "https://example.org/", "secret-key",
            )
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("secret-key", str(result))
        self.assertNotIn("key disabled", str(result))


if __name__ == "__main__":
    unittest.main()
