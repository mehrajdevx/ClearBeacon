import http.client
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from datetime import datetime, timezone

import server
from scamshield.storage import Database


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.database = Database(Path(cls.temp_dir.name) / "test.sqlite3")
        cls.httpd = server.ScamShieldServer(("127.0.0.1", 0), server.RequestHandler, cls.database)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls.temp_dir.cleanup()

    def setUp(self):
        server.ADMIN_TOKEN = "test-moderator-token"
        server.RequestHandler.requests_by_ip.clear()
        server.RequestHandler.ai_requests_by_ip.clear()
        connection = sqlite3.connect(self.database.path)
        try:
            connection.execute("DELETE FROM clarifications")
            connection.execute("DELETE FROM appeals")
            connection.execute("DELETE FROM audit_log")
            connection.execute("DELETE FROM reports")
            connection.execute("DELETE FROM result_feedback")
            connection.execute("DELETE FROM threat_feeds")
            connection.execute("DELETE FROM scan_escalations")
            connection.commit()
        finally:
            connection.close()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        request_headers = {"Content-Type": "application/json"} if payload is not None else {}
        request_headers.update(headers or {})
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        result = json.loads(raw) if response.getheader("Content-Type", "").startswith("application/json") else raw
        connection.close()
        return response.status, result

    def test_health_and_homepage(self):
        status, health = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")
        self.assertNotIn("report_counts", health)
        self.assertNotIn("tracked_client_buckets", health)
        status, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b'id="sculpture-hero-root"', page)
        self.assertIn(b'id="theme-toggle-root"', page)
        self.assertIn(b'id="footer-root"', page)
        self.assertIn(b'href="/liquid-sculpture-hero.css"', page)
        self.assertIn(b'href="/footer.css"', page)
        self.assertIn(b'href="/theme.css"', page)
        self.assertIn(b'src="/theme-bootstrap.js"', page)
        self.assertIn(b'src="/assets/sculpture-hero.js"', page)
        status, hero_bundle = self.request("GET", "/assets/sculpture-hero.js")
        self.assertEqual(status, 200)
        self.assertIn(b"Start a quick check", hero_bundle)
        self.assertIn(b"Switch to night mode", hero_bundle)
        self.assertIn(b"Information", hero_bundle)
        status, hero_styles = self.request("GET", "/liquid-sculpture-hero.css")
        self.assertEqual(status, 200)
        self.assertIn(b".sh-root", hero_styles)
        status, ocr_worker = self.request("GET", "/assets/ocr/worker.min.js")
        self.assertEqual(status, 200)
        self.assertGreater(len(ocr_worker), 1000)
        for path, expected in (
            ("/footer.css", b".footer-main"),
            ("/theme.css", b'html[data-theme="dark"]'),
            ("/theme-bootstrap.js", b"clearbeacon-theme"),
            ("/sculpture-hero-desktop.webp", b"RIFF"),
            ("/sculpture-hero-mobile.webp", b"RIFF"),
            ("/sculpture-hero-desktop-dark.webp", b"RIFF"),
            ("/sculpture-hero-mobile-dark.webp", b"RIFF"),
        ):
            with self.subTest(path=path):
                status, asset = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertIn(expected, asset)
        self.assertNotIn(b"Moderator access", page)
        status, admin_page = self.request("GET", "/admin")
        self.assertEqual(status, 200)
        self.assertIn(b"Reviewer console", admin_page)
        self.assertIn(b'<label for="bulk-reason">Reason for all selected actions</label>', admin_page)
        self.assertIn(b"noindex, nofollow", admin_page)
        self.assertIn(b'id="theme-toggle"', admin_page)
        self.assertIn(b'src="/admin-theme.js"', admin_page)
        self.assertIn(b'id="admin-sidebar"', admin_page)
        self.assertIn(b'href="#reports-panel"', admin_page)
        self.assertIn(b'href="/admin-template.css"', admin_page)
        status, admin_styles = self.request("GET", "/admin-template.css")
        self.assertEqual(status, 200)
        self.assertIn(b".admin-sidebar", admin_styles)
        self.assertIn(b"admin-sidebar-collapsed", admin_styles)
        status, privacy_page = self.request("GET", "/privacy.html")
        self.assertEqual(status, 200)
        self.assertIn(b"PRE-LAUNCH DRAFT", privacy_page)
        self.assertIn(b"Project operator: <strong>Fatima Abid</strong>", privacy_page)
        self.assertIn(b"operating as an individual in Pakistan", privacy_page)
        self.assertIn(b"Privacy contact: <strong>Not set up.</strong>", privacy_page)
        self.assertIn(b"currently runs on Vercel", privacy_page)
        self.assertIn(b"temporary, per-instance storage", privacy_page)
        self.assertIn(b"may be unavailable or lost", privacy_page)
        self.assertIn(b"may include minors", privacy_page)
        self.assertIn(b"noindex, nofollow", privacy_page)

    def test_invalid_scan_is_a_client_error(self):
        status, response = self.request("POST", "/api/check/url", {"url": "http://127.0.0.1"})
        self.assertEqual(status, 400)
        self.assertIn("Private or reserved", response["error"])

    def test_ai_review_runs_automatically_and_does_not_create_a_report(self):
        body = {"input_type": "message", "text": "Please verify your account.", "locale": "en"}
        with patch.dict(server.os.environ, {"GEMINI_API_KEY": ""}), patch("server.review_with_gemini") as ai_review:
            ai_review.return_value = {
                "provider": "Google Gemini",
                "model": "gemini-flash-latest",
                "risk_level": "caution",
                "summary": "Verify independently.",
                "findings": ["The request asks the user to verify an account."],
                "recommended_actions": ["Use the official app."],
                "disclaimer": "AI can be wrong.",
            }
            status, response = self.request("POST", "/api/check/ai", body)
            self.assertEqual(status, 200)
            self.assertEqual(response["provider"], "Google Gemini")
            ai_review.assert_called_once_with(
                "message", body["text"], "en", "", "gemini-flash-latest",
            )

        connection = sqlite3.connect(self.database.path)
        try:
            report_count = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(report_count, 0)

    def test_scan_escalation_is_server_generated_persistent_and_private(self):
        raw_message = (
            "URGENT: Verify your account immediately. Pay a registration fee. "
            "Send your OTP verification code. Click here to double your money with guaranteed profit."
        )
        status, result = self.request("POST", "/api/check/message", {"text": raw_message})
        self.assertEqual(status, 200)
        self.assertEqual(result["risk_label"], "high_risk")

        alerts = self.database.recent_scan_escalations()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["source"], "message-checker")
        self.assertNotIn(raw_message, str(alerts))
        self.assertEqual(Database(self.database.path).recent_scan_escalations(), alerts)

        auth = {"Authorization": f"Bearer {server.ADMIN_TOKEN}"}
        status, operations = self.request(
            "GET", "/api/admin/operations", headers=auth,
        )
        self.assertEqual(status, 200)
        self.assertTrue(any("verify independently" in alert["message"] for alert in operations["alerts"]))

    def test_bot_alert_cannot_be_forged_through_public_endpoint(self):
        body = {
            "severity": "critical",
            "title": "Forged alert",
            "summary": "This must not be accepted from a browser client.",
            "source": "link-checker",
        }
        status, _ = self.request("POST", "/api/bot/alert", body)
        self.assertEqual(status, 404)
        status, _ = self.request("GET", "/api/bot/alert")
        self.assertEqual(status, 404)
        self.assertEqual(self.database.recent_scan_escalations(), [])

    def test_expired_rate_limit_buckets_are_pruned(self):
        address = "192.0.2.1"
        server.RequestHandler.last_bucket_cleanup = 0
        server.RequestHandler.requests_by_ip[address].append(
            time.monotonic() - server.RATE_WINDOW_SECONDS - 1,
        )
        status, _ = self.request("POST", "/api/check/checklist", {"scenario": "payment"})
        self.assertEqual(status, 200)
        self.assertNotIn(address, server.RequestHandler.requests_by_ip)

    def test_additional_local_checks_and_public_directory(self):
        status, headers = self.request("POST", "/api/check/email-headers", {
            "headers": "From: alerts@example.invalid\nReply-To: collect@attacker.invalid\n",
        })
        self.assertEqual(status, 200)
        self.assertEqual(headers["risk_label"], "caution")
        self.assertTrue(any("Reply-To" in finding for finding in headers["findings"]))
        status, advice = self.request("POST", "/api/check/context", {
            "kind": "marketplace",
            "text": "Pay the urgent shipping fee outside the platform.",
        })
        self.assertEqual(status, 200)
        self.assertEqual(advice["risk_label"], "caution")
        status, organization = self.request("POST", "/api/check/organization", {
            "domain": "reportfraud.ftc.gov.attacker.invalid",
        })
        self.assertEqual(status, 200)
        self.assertEqual(organization["matches"], [])
        status, checklist = self.request("POST", "/api/check/checklist", {"scenario": "payment"})
        self.assertEqual(status, 200)
        self.assertEqual(len(checklist["items"]), 4)
        status, directory = self.request("GET", "/api/public/organizations")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(directory["organizations"]), 5)
        organizations_by_country = {
            organization["country"]: organization for organization in directory["organizations"]
        }
        for country in (
            "United Kingdom", "Australia", "Spain", "Mexico", "Pakistan", "United Arab Emirates",
        ):
            self.assertIn(country, organizations_by_country)
            self.assertTrue(organizations_by_country[country]["url"].startswith("https://"))
        status, trends = self.request("GET", "/api/public/trends")
        self.assertEqual(status, 200)
        self.assertEqual(trends["minimum_group_size"], 5)
        self.assertEqual(trends["verified_reports_by_category"], [])

    def test_structured_report_export_and_private_notes(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job",
            "target": "jobs.example.invalid",
            "summary": "A recruiter requested an upfront job fee.",
            "contact_channel": "social",
            "incident_date": "2026-10-12",
            "locale": "bn",
        })
        self.assertEqual(status, 201)
        status, exported = self.request("POST", "/api/reports/export", {"reference": created["reference"]})
        self.assertEqual(status, 200)
        self.assertEqual(exported["report"]["contact_channel"], "social")
        self.assertEqual(exported["report"]["locale"], "bn")
        self.assertEqual(exported["report"]["incident_date"], "2026-10-12")
        auth = {"Authorization": "Bearer test-moderator-token"}
        report_id = self.database.admin_reports("all")[0]["id"]
        status, _ = self.request("PATCH", f"/api/admin/reports/{report_id}/notes", {
            "kind": "handoff", "content": "Escalate for a second independent review.",
        }, auth)
        self.assertEqual(status, 200)
        status, notes = self.request("GET", f"/api/admin/reports/{report_id}/notes", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(notes["notes"][0]["kind"], "handoff")
        self.assertEqual(notes["notes"][0]["author"], "legacy-admin")
        status, public_status = self.request("POST", "/api/reports/status", {"token": created["reference"]})
        self.assertEqual(status, 200)
        self.assertNotIn("summary", public_status)
        self.assertNotIn("notes", public_status)

    def test_public_trends_suppress_groups_under_five(self):
        auth = {"Authorization": "Bearer test-moderator-token"}
        for index in range(5):
            status, created = self.request("POST", "/api/reports", {
                "category": "payment", "target": f"payee-{index}.example.invalid",
                "summary": f"An unexpected payment was requested by seller number {index}.",
            })
            self.assertEqual(status, 201)
            report_id = next(report["id"] for report in self.database.admin_reports("pending") if report["target"] == f"payee-{index}.example.invalid")
            status, _ = self.request("PATCH", f"/api/admin/reports/{report_id}", {
                "status": "verified", "reason": "Independent evidence reviewed.",
            }, auth)
            self.assertEqual(status, 200)
        status, trends = self.request("GET", "/api/public/trends")
        self.assertEqual(status, 200)
        self.assertIn({"category": "payment", "count": 5}, trends["verified_reports_by_category"])

    def test_message_check_accepts_all_supported_locales(self):
        for locale, text in (
            ("es", "código otp"),
            ("fr", "code de vérification"),
            ("hi", "ओटीपी"),
            ("ar", "رمز OTP"),
            ("bn", "ওটিপি"),
        ):
            with self.subTest(locale=locale):
                status, response = self.request("POST", "/api/check/message", {
                    "text": f"Please send the {text} now",
                    "locale": locale,
                })
                self.assertEqual(status, 200)
                self.assertEqual(response["locale"], locale)
                self.assertNotEqual(response["evidence"][0]["text"], "The message asks for a password, PIN, OTP, or verification code.")

    def test_unsupported_locale_is_rejected(self):
        for locale in ("xx",):
            with self.subTest(locale=locale):
                status, response = self.request("POST", "/api/check/message", {
                    "text": "Suspicious text here",
                    "locale": locale,
                })
                self.assertEqual(status, 400)
                self.assertIn("supported language", response["error"])

    def test_non_string_locale_is_rejected_without_server_error(self):
        status, response = self.request("POST", "/api/check/message", {
            "text": "Suspicious text here",
            "locale": [],
        })
        self.assertEqual(status, 400)
        self.assertIn("supported language", response["error"])

    def test_report_is_private_and_requires_authorized_moderation(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job",
            "target": "",
            "summary": "Asked to pay an upfront registration fee.",
        })
        self.assertEqual(status, 201)
        self.assertEqual(created["status"], "pending")
        self.assertNotIn("asked to pay", str(created).lower())

        status, queue = self.request(
            "GET",
            "/api/admin/reports",
            headers={"Authorization": f"Bearer {server.ADMIN_TOKEN}"},
        )
        self.assertEqual(status, 200)
        report = next(report for report in queue["reports"] if report["target"] == "(not provided)")
        self.assertEqual(report["target"], "(not provided)")

        status, _ = self.request("PATCH", f"/api/admin/reports/{report['id']}", {
            "status": "verified",
            "reason": "Reviewed supporting evidence.",
        })
        self.assertEqual(status, 401)
        status, _ = self.request("PATCH", f"/api/admin/reports/{report['id']}", {
            "status": "verified",
            "reason": "Reviewed supporting evidence.",
        }, {"Authorization": "Bearer test-moderator-token"})
        self.assertEqual(status, 200)

        status, lookup = self.request("POST", "/api/reports/status", {"token": created["reference"]})
        self.assertEqual(status, 200)
        self.assertEqual(lookup["status"], "verified")

    def test_admin_unavailable_without_configured_token(self):
        server.ADMIN_TOKEN = ""
        status, response = self.request("GET", "/api/admin/reports")
        self.assertEqual(status, 503)
        self.assertIn("not configured", response["error"])

    def test_admin_dashboard_filters_and_audit_history(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job",
            "target": "example.org",
            "summary": "Asked to pay an upfront registration fee.",
        })
        self.assertEqual(status, 201)
        auth = {"Authorization": "Bearer test-moderator-token"}
        status, overview = self.request("GET", "/api/admin/overview", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(overview["counts"]["pending"], 1)
        status, queue = self.request("GET", "/api/admin/reports?status=all", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(len(queue["reports"]), 1)
        status, invalid_filter = self.request("GET", "/api/admin/reports?status=unknown", headers=auth)
        self.assertEqual(status, 400)
        report_id = queue["reports"][0]["id"]
        status, _ = self.request(
            "PATCH",
            f"/api/admin/reports/{report_id}",
            {"status": "verified", "reason": "Evidence reviewed."},
            auth,
        )
        self.assertEqual(status, 200)
        status, queue = self.request("GET", "/api/admin/reports?status=pending", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(queue["reports"], [])
        status, overview = self.request("GET", "/api/admin/overview", headers=auth)
        self.assertEqual(overview["counts"]["verified"], 1)
        status, audit = self.request("GET", "/api/admin/audit", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(audit["entries"][0]["reason"], "Evidence reviewed.")

    def test_report_appeal_is_private_and_acceptance_reopens_report(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job",
            "target": "example.org",
            "summary": "Asked to pay an upfront registration fee.",
        })
        self.assertEqual(status, 201)
        auth = {"Authorization": "Bearer test-moderator-token"}
        status, queue = self.request("GET", "/api/admin/reports", headers=auth)
        report_id = queue["reports"][0]["id"]
        status, _ = self.request(
            "PATCH",
            f"/api/admin/reports/{report_id}",
            {"status": "rejected", "reason": "Initial review found insufficient evidence."},
            auth,
        )
        self.assertEqual(status, 200)

        appeal = {"reference": created["reference"], "details": "I have an official message confirming the request was fraudulent."}
        status, response = self.request("POST", "/api/reports/appeals", appeal)
        self.assertEqual(status, 201)
        self.assertEqual(response["status"], "pending")
        status, duplicate = self.request("POST", "/api/reports/appeals", appeal)
        self.assertEqual(status, 409)
        status, report_status = self.request("POST", "/api/reports/status", {"token": created["reference"]})
        self.assertEqual(report_status["appeal_status"], "pending")

        status, appeals = self.request("GET", "/api/admin/appeals", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(len(appeals["appeals"]), 1)
        appeal_id = appeals["appeals"][0]["id"]
        status, _ = self.request(
            "PATCH",
            f"/api/admin/appeals/{appeal_id}",
            {"status": "accepted", "reason": "New evidence warrants another review."},
            auth,
        )
        self.assertEqual(status, 200)
        status, report_status = self.request("POST", "/api/reports/status", {"token": created["reference"]})
        self.assertEqual(report_status["status"], "pending")
        self.assertEqual(report_status["appeal_status"], "accepted")
        status, overview = self.request("GET", "/api/admin/overview", headers=auth)
        self.assertEqual(overview["counts"]["pending"], 1)
        self.assertEqual(overview["counts"]["appeals"], 0)

    def test_named_reviewer_login_and_role_restrictions(self):
        original = server.REVIEWER_ACCOUNTS
        salt = "1a" * 16
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", b"correct-horse-battery", bytes.fromhex(salt), server.PBKDF2_ITERATIONS,
        ).hex()
        server.REVIEWER_ACCOUNTS = {
            "case-reviewer": {"salt": salt, "password_hash": password_hash, "role": "reviewer"},
        }
        try:
            status, denied = self.request("POST", "/api/admin/login", {
                "username": "case-reviewer", "password": "incorrect",
            })
            self.assertEqual(status, 401)
            status, login = self.request("POST", "/api/admin/login", {
                "username": "case-reviewer", "password": "correct-horse-battery",
            })
            self.assertEqual(status, 200)
            self.assertEqual(login["role"], "reviewer")
            headers = {"Authorization": f"Bearer {login['token']}"}
            status, overview = self.request("GET", "/api/admin/overview", headers=headers)
            self.assertEqual(status, 200)
            _, assigned_report = self.request("POST", "/api/reports", {
                "category": "job", "target": "assigned.example.invalid",
                "summary": "A recruiter requests a payment for an application.",
            })
            _, unassigned_report = self.request("POST", "/api/reports", {
                "category": "job", "target": "unassigned.example.invalid",
                "summary": "A recruiter requests a payment for an application.",
            })
            assigned_id = next(
                report["id"] for report in self.database.admin_reports("pending")
                if report["target"] == "assigned.example.invalid"
            )
            self.assertTrue(self.database.assign_report(
                assigned_id, "case-reviewer", "Assign to the named reviewer.",
            ))
            status, queue = self.request("GET", "/api/admin/reports?status=pending", headers=headers)
            self.assertEqual(status, 200)
            self.assertEqual([report["target"] for report in queue["reports"]], ["assigned.example.invalid"])
            unassigned_id = next(
                report["id"] for report in self.database.admin_reports("pending")
                if report["target"] == "unassigned.example.invalid"
            )
            status, denied_review = self.request("PATCH", f"/api/admin/reports/{unassigned_id}", {
                "status": "verified", "reason": "Unassigned reports are not accessible.",
            }, headers)
            self.assertEqual(status, 403)
            status, response = self.request("PUT", "/api/admin/reports/bulk", {
                "report_ids": ["00000000-0000-0000-0000-000000000001"],
                "status": "verified",
                "reason": "Not allowed for a reviewer.",
            }, headers)
            self.assertEqual(status, 403)
            self.assertIn("Only administrators", response["error"])
            self.httpd.sessions[login["token"]] = (
                "case-reviewer", "reviewer", time.monotonic() - 1,
            )
            status, expired = self.request("GET", "/api/admin/overview", headers=headers)
            self.assertEqual(status, 401)
            self.assertIn("authorization", expired["error"].lower())
        finally:
            server.REVIEWER_ACCOUNTS = original

    def test_reviewer_appeals_and_audit_are_scoped_to_authorized_data(self):
        original = server.REVIEWER_ACCOUNTS
        reviewer_name = "appeal-reviewer"
        password_hash = "a" * 64
        server.REVIEWER_ACCOUNTS = {
            reviewer_name: {
                "salt": "1a" * 16,
                "password_hash": password_hash,
                "role": "reviewer",
            },
        }
        token = "test-reviewer-session"
        self.httpd.sessions[token] = (
            reviewer_name, "reviewer", time.monotonic() + 300, password_hash,
        )
        reviewer_auth = {"Authorization": f"Bearer {token}"}
        admin_auth = {"Authorization": f"Bearer {server.ADMIN_TOKEN}"}
        try:
            reports = {}
            for target in ("assigned-appeal.example.invalid", "other-appeal.example.invalid"):
                status, created = self.request("POST", "/api/reports", {
                    "category": "job",
                    "target": target,
                    "summary": "The recruiter requested an advance payment.",
                })
                self.assertEqual(status, 201)
                reports[target] = created

            report_ids = {
                report["target"]: report["id"]
                for report in self.database.admin_reports("pending")
                if report["target"] in {target for target in reports}
            }
            self.assertTrue(self.database.assign_report(
                report_ids["assigned-appeal.example.invalid"],
                reviewer_name,
                "Assign appeal to reviewer.",
            ))
            for target, report_id in report_ids.items():
                self.assertTrue(self.database.review_report(
                    report_id, "rejected", f"Initial review of {target}.",
                ))
                status, appeal = self.request("POST", "/api/reports/appeals", {
                    "reference": reports[target]["reference"],
                    "details": f"Please reconsider the report for {target}.",
                })
                self.assertEqual(status, 201)

            status, all_appeals = self.request("GET", "/api/admin/appeals", headers=admin_auth)
            self.assertEqual(status, 200)
            self.assertEqual(len(all_appeals["appeals"]), 2)
            unassigned_appeal_id = next(
                appeal["id"] for appeal in all_appeals["appeals"]
                if "other-appeal" in appeal["details"]
            )
            assigned_appeal_id = next(
                appeal["id"] for appeal in all_appeals["appeals"]
                if "assigned-appeal" in appeal["details"]
            )

            status, reviewer_appeals = self.request(
                "GET", "/api/admin/appeals", headers=reviewer_auth,
            )
            self.assertEqual(status, 200)
            self.assertEqual(len(reviewer_appeals["appeals"]), 1)
            self.assertNotIn("reference", reviewer_appeals["appeals"][0])
            status, _ = self.request(
                "PATCH", f"/api/admin/appeals/{unassigned_appeal_id}",
                {"status": "accepted", "reason": "Attempt unauthorized appeal review."},
                reviewer_auth,
            )
            self.assertEqual(status, 403)
            status, _ = self.request(
                "PATCH", f"/api/admin/appeals/{assigned_appeal_id}",
                {"status": "accepted", "reason": "Reconsidered assigned appeal."},
                reviewer_auth,
            )
            self.assertEqual(status, 200)

            for path in ("/api/admin/audit", "/api/admin/audit/export"):
                status, _ = self.request("GET", path, headers=reviewer_auth)
                self.assertEqual(status, 403)
        finally:
            self.httpd.sessions.pop(token, None)
            server.REVIEWER_ACCOUNTS = original

    def test_private_clarification_reply_and_protected_audit_export(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job", "target": "clarification.example.invalid",
            "summary": "A recruiter requested money before an interview.",
        })
        self.assertEqual(status, 201)
        report_id = next(
            report["id"] for report in self.database.admin_reports("pending")
            if report["target"] == "clarification.example.invalid"
        )
        auth = {"Authorization": f"Bearer {server.ADMIN_TOKEN}"}
        status, result = self.request("POST", "/api/admin/clarifications", {
            "report_id": report_id, "message": "Please clarify when the payment was requested.",
        }, auth)
        self.assertEqual(status, 201)
        status, status_result = self.request("POST", "/api/reports/status", {
            "token": created["reference"],
        })
        self.assertEqual(status, 200)
        self.assertEqual(status_result["clarifications"][0]["status"], "open")
        status, reply = self.request("POST", "/api/reports/clarifications/reply", {
            "reference": created["reference"],
            "clarification_id": result["id"],
            "message": "The request arrived before any interview was scheduled.",
        })
        self.assertEqual(status, 201)
        status, status_result = self.request("POST", "/api/reports/status", {
            "token": created["reference"],
        })
        self.assertEqual(status_result["clarifications"][0]["status"], "answered")
        status, _ = self.request("GET", "/api/admin/audit/export")
        self.assertEqual(status, 401)
        status, export = self.request("GET", "/api/admin/audit/export", headers=auth)
        self.assertEqual(status, 200)
        self.assertIn(b"clarification_requested", export)

    def test_admin_threat_feed_staging_activation_and_rollback(self):
        auth = {"Authorization": f"Bearer {server.ADMIN_TOKEN}"}
        first = {
            "provider": "First test source",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "domains": ["phish.example.com"],
        }
        status, _ = self.request("POST", "/api/admin/feed/stage", {"feed": first}, auth)
        self.assertEqual(status, 201)
        status, staged = self.request("GET", "/api/admin/feed", headers=auth)
        feed_id = staged["versions"][0]["id"]
        status, activated = self.request("PUT", "/api/admin/feed/activate", {"id": feed_id}, auth)
        self.assertEqual(status, 200)
        status, result = self.request("POST", "/api/check/url", {"url": "https://phish.example.com/login"})
        self.assertEqual(status, 200)
        self.assertEqual(result["risk_label"], "known_malicious")

        second = {
            "provider": "Second test source",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "domains": ["other.example.com"],
        }
        status, _ = self.request("POST", "/api/admin/feed/stage", {"feed": second}, auth)
        status, staged = self.request("GET", "/api/admin/feed", headers=auth)
        second_id = staged["versions"][0]["id"]
        status, _ = self.request("PUT", "/api/admin/feed/activate", {"id": second_id}, auth)
        self.assertEqual(status, 200)
        status, _ = self.request("PUT", "/api/admin/feed/rollback", {}, auth)
        self.assertEqual(status, 200)
        status, result = self.request("POST", "/api/check/url", {"url": "https://phish.example.com/login"})
        self.assertEqual(result["risk_label"], "known_malicious")

    def test_admin_can_revoke_named_account_sessions(self):
        original = server.REVIEWER_ACCOUNTS
        salt = "3c" * 16
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", b"revocation-test-password", bytes.fromhex(salt), server.PBKDF2_ITERATIONS,
        ).hex()
        server.REVIEWER_ACCOUNTS = {
            "revoked-user": {"salt": salt, "password_hash": password_hash, "role": "reviewer"},
        }
        try:
            status, login = self.request("POST", "/api/admin/login", {
                "username": "revoked-user", "password": "revocation-test-password",
            })
            self.assertEqual(status, 200)
            status, result = self.request("POST", "/api/admin/sessions/revoke", {
                "username": "revoked-user",
            }, {"Authorization": f"Bearer {server.ADMIN_TOKEN}"})
            self.assertEqual(status, 200)
            self.assertEqual(result["revoked"], 1)
            status, _ = self.request("GET", "/api/admin/overview", headers={
                "Authorization": f"Bearer {login['token']}",
            })
            self.assertEqual(status, 401)
        finally:
            server.REVIEWER_ACCOUNTS = original

    def test_admin_can_assign_reports_and_bulk_review(self):
        original = server.REVIEWER_ACCOUNTS
        salt = "2b" * 16
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", b"admin-test-password", bytes.fromhex(salt), server.PBKDF2_ITERATIONS,
        ).hex()
        server.REVIEWER_ACCOUNTS = {
            "case-admin": {"salt": salt, "password_hash": password_hash, "role": "admin"},
            "case-reviewer": {"salt": salt, "password_hash": password_hash, "role": "reviewer"},
        }
        try:
            status, login = self.request("POST", "/api/admin/login", {
                "username": "case-admin", "password": "admin-test-password",
            })
            self.assertEqual(status, 200)
            headers = {"Authorization": f"Bearer {login['token']}"}
            created_reports = []
            for target in ("first.example.invalid", "second.example.invalid"):
                status, created = self.request("POST", "/api/reports", {
                    "category": "job", "target": target,
                    "summary": "A recruiter requested an unexpected payment.",
                })
                self.assertEqual(status, 201)
                created_reports.append(created)
            status, queue = self.request("GET", "/api/admin/reports?status=pending", headers=headers)
            self.assertEqual(status, 200)
            reports = {report["target"]: report["id"] for report in queue["reports"]}
            assigned_id = reports["first.example.invalid"]
            bulk_id = reports["second.example.invalid"]
            status, result = self.request("PATCH", "/api/admin/reports/assign", {
                "report_id": assigned_id, "reviewer": "case-reviewer",
                "status": "assigned", "reason": "Route to the regional reviewer.",
            }, headers)
            self.assertEqual(status, 200)
            self.assertTrue(result["updated"])
            status, result = self.request("PUT", "/api/admin/reports/bulk", {
                "report_ids": [bulk_id], "status": "escalated",
                "reason": "Escalate for additional evidence review.",
            }, headers)
            self.assertEqual(status, 200)
            self.assertEqual(result["updated"], 1)
            status, all_reports = self.request("GET", "/api/admin/reports?status=all", headers=headers)
            self.assertEqual(status, 200)
            by_target = {report["target"]: report for report in all_reports["reports"]}
            self.assertEqual(by_target["first.example.invalid"]["assigned_to"], "case-reviewer")
            self.assertEqual(by_target["second.example.invalid"]["status"], "escalated")
        finally:
            server.REVIEWER_ACCOUNTS = original

    def test_retention_cleanup_removes_old_private_data(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job", "target": "expired.example.invalid",
            "summary": "A recruiter requested an unexpected payment.",
        })
        self.assertEqual(status, 201)
        self.request("POST", "/api/feedback", {
            "input_type": "message", "input": "sensitive text",
            "risk_label": "unknown", "details": "The result missed important context.",
        })
        connection = sqlite3.connect(self.database.path)
        try:
            connection.execute("UPDATE reports SET created_at = '2000-01-01T00:00:00+00:00' WHERE reference = ?", (created["reference"],))
            connection.execute("UPDATE result_feedback SET created_at = '2000-01-01T00:00:00+00:00'")
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(self.database.delete_expired_reports(365), 2)
        self.assertIsNone(self.database.get_report_by_token(created["reference"]))
        self.assertEqual(self.database.pending_result_feedback(), [])

    def test_feedback_is_private_and_report_delete_erases_related_rows(self):
        status, created = self.request("POST", "/api/reports", {
            "category": "job",
            "target": "example.org",
            "summary": "Asked to pay an upfront registration fee.",
        })
        self.assertEqual(status, 201)
        duplicate_status, duplicate = self.request("POST", "/api/reports", {
            "category": "job",
            "target": " EXAMPLE.ORG ",
            "summary": "They requested an upfront job registration payment.",
        })
        self.assertEqual(duplicate_status, 201)
        self.assertTrue(duplicate["possible_duplicate"])

        status, submitted_feedback = self.request("POST", "/api/feedback", {
            "input_type": "message", "input": "private raw message data",
            "risk_label": "unknown", "details": "The result missed a suspicious payment request.",
        })
        self.assertEqual(status, 201)
        status, feedback_status = self.request("POST", "/api/feedback/status", {
            "reference": submitted_feedback["reference"],
        })
        self.assertEqual(status, 200)
        self.assertEqual(feedback_status["status"], "pending")
        connection = sqlite3.connect(self.database.path)
        try:
            feedback_row = connection.execute("SELECT input_hash, details FROM result_feedback").fetchone()
            self.assertNotIn("private raw message data", str(feedback_row))
            self.assertEqual(len(feedback_row[0]), 64)
        finally:
            connection.close()

        auth = {"Authorization": "Bearer test-moderator-token"}
        status, feedback = self.request("GET", "/api/admin/feedback", headers=auth)
        self.assertEqual(status, 200)
        self.assertEqual(len(feedback["feedback"]), 1)
        status, _ = self.request("PATCH", f"/api/admin/feedback/{feedback['feedback'][0]['id']}", {}, auth)
        self.assertEqual(status, 200)
        status, feedback_status = self.request("POST", "/api/feedback/status", {
            "reference": submitted_feedback["reference"],
        })
        self.assertEqual(status, 200)
        self.assertEqual(feedback_status["status"], "reviewed")
        status, deleted = self.request("POST", "/api/reports/delete", {"reference": created["reference"]})
        self.assertEqual(status, 200)
        self.assertTrue(deleted["deleted"])
        status, lookup = self.request("POST", "/api/reports/status", {"token": created["reference"]})
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
