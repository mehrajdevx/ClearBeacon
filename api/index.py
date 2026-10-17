from __future__ import annotations

import io
import os
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

from server import RequestHandler  # noqa: E402
from scamshield.storage import Database  # noqa: E402


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
            "script-src 'self'; img-src 'self' data:; connect-src 'self'; "
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

    handler_method(request)
    body = request.wfile.getvalue()
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
