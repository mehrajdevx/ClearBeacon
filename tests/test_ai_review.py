from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from scamshield.ai_review import AIReviewError, review_with_gemini


class GeminiReviewTests(unittest.TestCase):
    def test_review_uses_server_key_and_validates_structured_output(self):
        provider_result = {
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "internal reasoning is not the review", "thought": True},
                        {
                            "text": json.dumps({
                                "risk_level": "caution",
                                "summary": "Verify the sender independently.",
                                "findings": ["The message uses urgency."],
                                "recommended_actions": ["Use the official app."],
                            }),
                        },
                    ],
                },
            }],
        }
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(provider_result).encode()

        with patch("scamshield.ai_review.urlopen", return_value=response) as open_url:
            result = review_with_gemini(
                "message", "untrusted text", "en", "secret-key",
            )

        request = open_url.call_args.args[0]
        self.assertEqual(request.get_header("X-goog-api-key"), "secret-key")
        self.assertNotIn("secret-key", request.full_url)
        request_body = json.loads(request.data)
        self.assertEqual(
            request_body["generationConfig"]["thinkingConfig"],
            {"thinkingLevel": "low"},
        )
        self.assertEqual(request_body["generationConfig"]["maxOutputTokens"], 1024)
        self.assertEqual(open_url.call_args.kwargs["timeout"], 30)
        self.assertEqual(result["risk_level"], "caution")
        self.assertEqual(result["findings"], ["The message uses urgency."])

    def test_missing_key_does_not_contact_provider(self):
        with patch("scamshield.ai_review.urlopen") as open_url:
            with self.assertRaisesRegex(AIReviewError, "not configured"):
                review_with_gemini("url", "https://example.org", "en", "")
        open_url.assert_not_called()

    def test_primary_limit_discovers_and_uses_supported_flash_models(self):
        primary_quota_error = HTTPError(
            "https://generativelanguage.googleapis.com", 429,
            "quota", {}, None,
        )
        unsupported_model_error = HTTPError(
            "https://generativelanguage.googleapis.com", 404,
            "model unavailable", {}, None,
        )
        model_list = MagicMock()
        model_list.__enter__.return_value.read.return_value = json.dumps({
            "models": [
                {
                    "name": "models/gemini-2.5-flash",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/gemini-2.5-flash-lite",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/gemini-3.1-pro-preview",
                    "supportedGenerationMethods": ["generateContent"],
                },
            ],
        }).encode()
        provider_result = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "risk_level": "unknown",
                            "summary": "The URL alone is not enough to verify this site.",
                            "findings": [],
                            "recommended_actions": ["Verify independently."],
                        }),
                    }],
                },
            }],
        }
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(provider_result).encode()

        with patch(
            "scamshield.ai_review.urlopen",
            side_effect=[primary_quota_error, model_list, unsupported_model_error, response],
        ) as open_url:
            result = review_with_gemini("url", "https://example.org", "en", "secret-key")

        first_request = open_url.call_args_list[0].args[0]
        discovery_request = open_url.call_args_list[1].args[0]
        first_fallback_request = open_url.call_args_list[2].args[0]
        fallback_request = open_url.call_args_list[3].args[0]
        self.assertIn("/models/gemini-flash-latest:", first_request.full_url)
        self.assertEqual(discovery_request.full_url, "https://generativelanguage.googleapis.com/v1beta/models")
        self.assertIn("/models/gemini-2.5-flash-lite:", first_fallback_request.full_url)
        self.assertIn("/models/gemini-2.5-flash:", fallback_request.full_url)
        self.assertEqual(result["model"], "gemini-2.5-flash")

    def test_quota_on_available_models_is_reported_as_rate_limit(self):
        errors = [
            HTTPError("https://generativelanguage.googleapis.com", 429, "quota", {}, None),
            HTTPError("https://generativelanguage.googleapis.com", 429, "quota", {}, None),
        ]
        model_list = MagicMock()
        model_list.__enter__.return_value.read.return_value = json.dumps({
            "models": [{
                "name": "models/gemini-2.5-flash",
                "supportedGenerationMethods": ["generateContent"],
            }],
        }).encode()
        with patch(
            "scamshield.ai_review.urlopen",
            side_effect=[errors[0], model_list, errors[1]],
        ) as open_url:
            with self.assertRaisesRegex(AIReviewError, "quota or rate limits") as raised:
                review_with_gemini("url", "https://example.org", "en", "secret-key")
        self.assertEqual(raised.exception.status, 429)
        self.assertEqual(open_url.call_count, 3)

    def test_other_provider_http_errors_include_status_without_response_body(self):
        error = HTTPError(
            "https://generativelanguage.googleapis.com", 503,
            "provider unavailable", {}, None,
        )
        with patch("scamshield.ai_review.urlopen", side_effect=error):
            with self.assertRaisesRegex(AIReviewError, "Gemini returned HTTP 503") as raised:
                review_with_gemini("url", "https://example.org", "en", "secret-key")
        self.assertNotIn("provider unavailable", str(raised.exception))

    def test_transient_provider_error_is_retried_once(self):
        error = HTTPError(
            "https://generativelanguage.googleapis.com", 503,
            "provider unavailable", {}, None,
        )
        provider_result = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "risk_level": "low",
                            "summary": "No strong scam indicators were found.",
                            "findings": [],
                            "recommended_actions": ["Verify independently."],
                        }),
                    }],
                },
            }],
        }
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(provider_result).encode()
        with (
            patch("scamshield.ai_review.urlopen", side_effect=[error, response]) as open_url,
            patch("scamshield.ai_review.time.sleep") as sleep,
        ):
            result = review_with_gemini(
                "message", "untrusted content", "en", "secret-key",
            )
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(open_url.call_count, 2)
        sleep.assert_called_once_with(0.5)

    def test_provider_block_reason_is_reported_without_echoing_content(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            "promptFeedback": {"blockReason": "SAFETY"},
        }).encode()
        with patch("scamshield.ai_review.urlopen", return_value=response):
            with self.assertRaisesRegex(AIReviewError, "provider block reason: SAFETY"):
                review_with_gemini("message", "sensitive input", "en", "secret-key")

    def test_invalid_json_output_is_reported_without_echoing_content(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            "candidates": [{
                "finishReason": "STOP",
                "content": {"parts": [{"text": "sensitive malformed output"}]},
            }],
        }).encode()
        with patch("scamshield.ai_review.urlopen", return_value=response):
            with self.assertRaisesRegex(AIReviewError, "non-JSON output") as raised:
                review_with_gemini("message", "sensitive input", "en", "secret-key")
        self.assertNotIn("sensitive malformed output", str(raised.exception))

    def test_network_timeout_is_actionable_without_exposing_submitted_text(self):
        sensitive_text = "private one-time passcode"
        with patch(
            "scamshield.ai_review.urlopen",
            side_effect=URLError(TimeoutError("connection timed out")),
        ):
            with self.assertRaisesRegex(AIReviewError, "connection timed out") as raised:
                review_with_gemini("message", sensitive_text, "en", "secret-key")
        self.assertNotIn(sensitive_text, str(raised.exception))

    def test_invalid_model_name_is_rejected(self):
        with self.assertRaisesRegex(AIReviewError, "model name is invalid"):
            review_with_gemini(
                "url", "https://example.org", "en", "secret-key", "../other",
            )


if __name__ == "__main__":
    unittest.main()
