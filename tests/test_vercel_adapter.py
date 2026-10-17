import hashlib
import io
import os
import json
import tempfile
import time
import unittest
from pathlib import Path
from wsgiref.util import setup_testing_defaults

TEST_DB_DIR = tempfile.TemporaryDirectory()
os.environ["SCAMSHIELD_DB"] = str(Path(TEST_DB_DIR.name) / "vercel-adapter-test.sqlite3")

import server
from api import index as vercel_adapter


def tearDownModule():
    TEST_DB_DIR.cleanup()


class VercelSessionTokenTests(unittest.TestCase):
    def setUp(self):
        self.original_secret = vercel_adapter.SESSION_SECRET
        self.original_accounts = server.REVIEWER_ACCOUNTS
        self.original_state = vercel_adapter.state
        vercel_adapter.SESSION_SECRET = "test-session-secret-that-is-at-least-32-bytes"
        salt = "b" * 32
        server.REVIEWER_ACCOUNTS = {
            "teacher": {
                "role": "admin",
                "password_hash": hashlib.pbkdf2_hmac(
                    "sha256", b"test-password", bytes.fromhex(salt), 310_000,
                ).hex(),
                "salt": salt,
            }
        }

    def tearDown(self):
        vercel_adapter.SESSION_SECRET = self.original_secret
        server.REVIEWER_ACCOUNTS = self.original_accounts
        vercel_adapter.state = self.original_state

    def request(self, method, path, body=None, headers=None, query=""):
        environ = {}
        setup_testing_defaults(environ)
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else b""
        environ.update({
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(encoded_body)),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(encoded_body),
            "REMOTE_ADDR": "127.0.0.1",
        })
        for key, value in (headers or {}).items():
            environ[f"HTTP_{key.upper().replace('-', '_')}"] = value
        response = {}
        result = b"".join(
            vercel_adapter.app(
                environ,
                lambda status, response_headers: response.update(
                    status=status, headers=response_headers,
                ),
            )
        )
        return response, result

    def test_signed_session_is_valid_across_function_instances(self):
        token = vercel_adapter._encode_admin_session(
            "teacher",
            "admin",
            time.time() + 1800,
            server.REVIEWER_ACCOUNTS["teacher"]["password_hash"],
        )

        session = vercel_adapter._decode_admin_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session[:2], ("teacher", "admin"))
        self.assertGreater(session[2], time.time())
        self.assertEqual(session[3], server.REVIEWER_ACCOUNTS["teacher"]["password_hash"])

    def test_tampered_expired_and_outdated_credential_tokens_are_rejected(self):
        password_hash = server.REVIEWER_ACCOUNTS["teacher"]["password_hash"]
        valid = vercel_adapter._encode_admin_session(
            "teacher", "admin", time.time() + 1800, password_hash,
        )
        expired = vercel_adapter._encode_admin_session(
            "teacher", "admin", time.time() - 1, password_hash,
        )
        tampered = valid[:-1] + ("A" if valid[-1] != "A" else "B")

        self.assertIsNone(vercel_adapter._decode_admin_session(tampered))
        self.assertIsNone(vercel_adapter._decode_admin_session(expired))
        server.REVIEWER_ACCOUNTS["teacher"]["password_hash"] = "c" * 64
        self.assertIsNone(vercel_adapter._decode_admin_session(valid))

    def test_login_token_authorizes_a_different_function_instance(self):
        login_response, body = self.request(
            "POST",
            "/api/index",
            {"username": "teacher", "password": "test-password"},
            query="path=admin%2Flogin",
        )
        self.assertTrue(login_response["status"].startswith("200"))
        self.assertEqual(
            int(dict(login_response["headers"])["Content-Length"]),
            len(body),
        )
        token = json.loads(body)["token"]
        self.assertIsNotNone(vercel_adapter._decode_admin_session(token))

        vercel_adapter.state = vercel_adapter.FunctionState()
        queue_response, queue_body = self.request(
            "GET",
            "/api/index",
            headers={"Authorization": f"Bearer {token}"},
            query="path=admin%2Freports",
        )
        self.assertTrue(queue_response["status"].startswith("200"))
        self.assertIn(b'"reports"', queue_body)


if __name__ == "__main__":
    unittest.main()
