from __future__ import annotations

import io
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, urlencode


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SCAMSHIELD_DB", "/tmp/clearbeacon.sqlite3")
os.environ.setdefault("SCAMSHIELD_HOST", "0.0.0.0")

import server as scamshield_server  # noqa: E402
from server import RequestHandler  # noqa: E402
from scamshield.storage import Database  # noqa: E402


SESSION_SECRET = os.environ.get("SCAMSHIELD_SESSION_SECRET", "")


class FunctionState:
    def __init__(self) -> None:
        self.database = Database(Path(os.environ["SCAMSHIELD_DB"]))
        self.started_at = time.monotonic()
        self.sessions: dict[str, tuple[str, str, float, str]] = {}


state = FunctionState()


class FunctionRequestHandler(RequestHandler):
    def send_response(self, code: int, message: str | None = None) -> None:
        self.status_code = code
        self.response_headers = []

    def send_header(self, keyword: str, value: str) -> None:
        self.response_headers.append((keyword, value))

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; "
            "script-src 'self' 'wasm-unsafe-eval'; img-src 'self' data:; connect-src 'self' https://tessdata.projectnaptha.com; "
            "worker-src 'self'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        self.send_header("Cache-Control", "no-store")


def app(environ: dict[str, object], start_response: Callable) -> list[bytes]:
    method = str(environ.get("REQUEST_METHOD", "GET")).upper()
    handler_method = getattr(FunctionRequestHandler, f"do_{method}", None)
    if method == "HEAD":
        handler_method = FunctionRequestHandler.do_GET
    if handler_method is None:
        body = b'{"error":"Method not allowed."}'
        start_response(
            "405 Method Not Allowed",
            [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body)))],
        )
        return [body]

    request = FunctionRequestHandler.__new__(FunctionRequestHandler)
    request.server = state
    request.command = method
    request.request_version = "HTTP/1.1"
    path = str(environ.get("PATH_INFO", "/"))
    query = str(environ.get("QUERY_STRING", ""))
    query_parameters = parse_qsl(query, keep_blank_values=True)
    route_parameter = next((value for key, value in query_parameters if key == "path"), None)
    if path == "/api/index" and route_parameter is not None:
        path = f"/api/{route_parameter.lstrip('/')}"
        query = urlencode([
            (key, value) for key, value in query_parameters if key != "path"
        ])
    request.path = f"{path}?{query}" if query else path
    request.rfile = io.BytesIO(environ.get("wsgi.input", io.BytesIO()).read())
    request.wfile = io.BytesIO()
    request.response_headers = []
    request.status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    request.headers = Message()
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").title()
            request.headers[name] = str(value)
    for key, header in (("CONTENT_TYPE", "Content-Type"), ("CONTENT_LENGTH", "Content-Length")):
        if key in environ:
            request.headers[header] = str(environ[key])
    request.client_address = (str(environ.get("REMOTE_ADDR", "unknown")), 0)

    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        token = authorization[7:]
        session = _decode_admin_session(token)
        if session is not None:
            username, role, expires_at, credential_hash = session
            request.server.sessions[token] = (
                username,
                role,
                time.monotonic() + max(0, expires_at - time.time()),
                credential_hash,
            )

    handler_method(request)
    body = request.wfile.getvalue()
    if request.status_code == HTTPStatus.OK and path == "/api/admin/login" and SESSION_SECRET:
        response = json.loads(body)
        original_token = response.get("token")
        session = state.sessions.pop(original_token, None) if isinstance(original_token, str) else None
        if session is not None:
            username, role, expires_at, credential_hash = session
            response["token"] = _encode_admin_session(
                username,
                role,
                time.time() + max(0, int(expires_at - time.monotonic())),
                credential_hash,
            )
            body = json.dumps(response, ensure_ascii=False).encode("utf-8")
            for index, (name, _) in enumerate(request.response_headers):
                if name.lower() == "content-length":
                    request.response_headers[index] = (name, str(len(body)))
                    break
    if method == "HEAD":
        body = b""
    if not any(name.lower() == "content-length" for name, _ in request.response_headers):
        request.response_headers.append(("Content-Length", str(len(body))))
    phrase = HTTPStatus(request.status_code).phrase
    start_response(
        f"{request.status_code} {phrase}",
        request.response_headers,
    )
    return [body]


def _encode_admin_session(username: str, role: str, expires_at: float, credential_hash: str) -> str:
    if len(SESSION_SECRET.encode("utf-8")) < 32:
        raise RuntimeError("SCAMSHIELD_SESSION_SECRET must contain at least 32 bytes.")
    payload = json.dumps(
        {
            "username": username,
            "role": role,
            "expires_at": int(expires_at),
            "credential_hash": credential_hash,
            "nonce": secrets.token_urlsafe(16),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"cb1.{encoded_payload}.{encoded_signature}"


def _decode_admin_session(token: str) -> tuple[str, str, int, str] | None:
    if not SESSION_SECRET or len(SESSION_SECRET.encode("utf-8")) < 32:
        return None
    try:
        version, encoded_payload, encoded_signature = token.split(".")
        if version != "cb1":
            return None
        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        expected_signature = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        payload = json.loads(
            base64.urlsafe_b64decode(
                encoded_payload + "=" * (-len(encoded_payload) % 4)
            )
        )
        username = payload["username"]
        role = payload["role"]
        expires_at = payload["expires_at"]
        credential_hash = payload["credential_hash"]
        account = scamshield_server.REVIEWER_ACCOUNTS.get(username)
        if (
            not isinstance(username, str)
            or not isinstance(role, str)
            or role not in {"admin", "reviewer"}
            or not isinstance(expires_at, int)
            or expires_at <= time.time()
            or not isinstance(credential_hash, str)
            or account is None
            or account["role"] != role
            or not hmac.compare_digest(account["password_hash"], credential_hash)
        ):
            return None
        return username, role, expires_at, credential_hash
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        return None
