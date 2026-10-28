"""A small local web server that the app window talks to.

It binds to 127.0.0.1 only, and every request must carry a token generated at
start-up, so other programs and web pages on the machine cannot use it. The
Host header is checked too, which blocks DNS-rebinding tricks.
"""

from __future__ import annotations

import json
import mimetypes
import re
import secrets
import shutil
import tempfile
import threading
import urllib.parse
import webbrowser
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import __version__
from ..ai import PROVIDERS, ProviderConfig, Settings
from ..ai.providers import LLMError, list_models, test_connection
from ..ai.settings import Privacy
from . import jobs, runs

UI = Path(__file__).parent / "ui"
_SAFE_NAME = re.compile(r"[^\w.\- ]+")


class Dialogs:
    """Native file dialogs. The window layer supplies a real one; without it the screen asks for paths."""

    available = False

    def pick_folder(self) -> list[str]:
        return []

    def pick_files(self) -> list[str]:
        return []

    def save_file(self, suggested: str) -> str | None:
        return None


class App:
    def __init__(self, dialogs: Dialogs | None = None):
        self.token = secrets.token_urlsafe(24)
        self.dialogs = dialogs or Dialogs()
        self.uploads = Path(tempfile.mkdtemp(prefix="loganalyser-uploads-"))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?t={self.token}"

    def serve_in_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        return thread

    def close(self) -> None:
        self.httpd.shutdown()
        shutil.rmtree(self.uploads, ignore_errors=True)

    # ------------------------------------------------------------------ API
    def state(self) -> dict:
        return {"version": __version__, "settings": Settings.load().public(), "history": runs.history(),
                "nativeDialogs": self.dialogs.available}

    def save_settings(self, body: dict) -> dict:
        settings = Settings.load()
        if body.get("active") in PROVIDERS:
            settings.active = body["active"]
        if "ai_enabled" in body:
            settings.ai_enabled = bool(body["ai_enabled"])
        privacy = body.get("privacy") or {}
        settings.privacy = Privacy(redact=bool(privacy.get("redact", settings.privacy.redact)),
                                   max_lines=max(20, min(2000, int(privacy.get("max_lines", settings.privacy.max_lines)))))
        for name, data in (body.get("providers") or {}).items():
            if name not in PROVIDERS or not isinstance(data, dict):
                continue
            current = settings.provider(name)
            settings.providers[name] = self._merge(current, data)
        settings.save()
        return Settings.load().public()

    @staticmethod
    def _merge(current: ProviderConfig, data: dict) -> ProviderConfig:
        """Apply edits from the screen. A blank key field keeps the saved key unless clearing was asked for."""
        key = current.api_key
        if data.get("clear_key"):
            key = ""
        elif data.get("api_key"):
            key = str(data["api_key"]).strip()
        effort = data.get("effort", current.effort)
        return replace(current,
                       model=str(data.get("model", current.model)).strip(),
                       base_url=str(data.get("base_url", current.base_url)).strip(),
                       api_version=str(data.get("api_version", current.api_version)).strip(),
                       effort=effort if effort in ("low", "medium", "high", "xhigh", "max") else "high",
                       api_key=key)

    def provider_for_test(self, body: dict) -> ProviderConfig:
        name = body.get("provider")
        if name not in PROVIDERS:
            raise ValueError("Unknown provider.")
        return self._merge(Settings.load().provider(name), body.get("config") or {})

    def save_upload(self, batch: str, relative: str, data: bytes) -> str:
        """Store a dropped file (when the window cannot tell us its path). Returns the batch folder."""
        if not re.fullmatch(r"[0-9a-f]{16}", batch):
            raise ValueError("Bad upload batch.")
        parts = [_SAFE_NAME.sub("_", p) for p in Path(relative).parts if p not in ("", ".", "..", "/", "\\")]
        if not parts:
            raise ValueError("Bad file name.")
        target = self.uploads / batch / Path(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return str(self.uploads / batch)

    # -------------------------------------------------------------- handler
    def _handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "LogAnalyser"

            def log_message(self, *args):  # keep the console quiet
                pass

            # ---- plumbing
            def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, data, status: int = 200):
                self._send(status, json.dumps(data, default=str).encode("utf-8"), "application/json; charset=utf-8")

            def _fail(self, message: str, status: int = 400):
                self._json({"error": message}, status)

            def _allowed(self) -> bool:
                host = (self.headers.get("Host") or "").lower()
                if host not in (f"127.0.0.1:{app.port}", f"localhost:{app.port}"):
                    return False
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                token = self.headers.get("X-Token") or (query.get("t") or [""])[0]
                return secrets.compare_digest(token, app.token)

            def _body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def _json_body(self) -> dict:
                try:
                    data = json.loads(self._body() or b"{}")
                except ValueError:
                    return {}
                return data if isinstance(data, dict) else {}

            # ---- routes
            def do_GET(self):
                if not self._allowed():
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain")
                path = urllib.parse.urlsplit(self.path).path
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                try:
                    if path == "/":
                        page = (UI / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", app.token)
                        return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
                    if path.startswith("/ui/"):
                        target = (UI / path[4:]).resolve()
                        if UI.resolve() not in target.parents or not target.is_file():
                            return self._fail("Not found", 404)
                        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                        return self._send(200, target.read_bytes(), ctype)
                    if path == "/api/state":
                        return self._json(app.state())
                    m = re.fullmatch(r"/api/jobs/([0-9a-f]{12})", path)
                    if m:
                        return self._json(jobs.get(m.group(1)).state())
                    m = re.fullmatch(r"/report/([0-9a-f]{12})", path)
                    if m:
                        body = runs.report_path(m.group(1)).read_bytes()
                        extra = {}
                        if query.get("download"):
                            extra["Content-Disposition"] = f'attachment; filename="log-report-{m.group(1)}.html"'
                        return self._send(200, body, "text/html; charset=utf-8", extra)
                    return self._fail("Not found", 404)
                except KeyError:
                    return self._fail("That item no longer exists.", 404)

            def do_DELETE(self):
                if not self._allowed():
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain")
                m = re.fullmatch(r"/api/runs/([0-9a-f]{12})", urllib.parse.urlsplit(self.path).path)
                if not m:
                    return self._fail("Not found", 404)
                try:
                    runs.delete(m.group(1))
                except KeyError:
                    return self._fail("That analysis no longer exists.", 404)
                return self._json({"ok": True})

            def do_POST(self):
                if not self._allowed():
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain")
                path = urllib.parse.urlsplit(self.path).path
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                try:
                    if path == "/api/upload":
                        folder = app.save_upload((query.get("batch") or [""])[0], (query.get("name") or [""])[0],
                                                 self._body())
                        return self._json({"folder": folder})
                    body = self._json_body()
                    if path == "/api/settings":
                        return self._json(app.save_settings(body))
                    if path == "/api/pick":
                        kind = body.get("kind")
                        paths = app.dialogs.pick_folder() if kind == "folder" else app.dialogs.pick_files()
                        return self._json({"paths": paths})
                    if path == "/api/providers/test":
                        try:
                            return self._json({"ok": True, **test_connection(app.provider_for_test(body))})
                        except LLMError as exc:
                            return self._json({"ok": False, "error": str(exc)})
                    if path == "/api/providers/models":
                        try:
                            return self._json({"models": list_models(app.provider_for_test(body))})
                        except LLMError as exc:
                            return self._json({"models": [], "error": str(exc)})
                    if path == "/api/analyse":
                        sources = [str(s) for s in body.get("sources") or [] if str(s).strip()]
                        if not sources:
                            return self._fail("Choose a folder or some files first.")
                        job = jobs.start_analysis(sources, [str(s) for s in body.get("baseline") or []],
                                                  [str(m) for m in body.get("match") or [] if str(m).strip()],
                                                  bool(body.get("ai")), body.get("provider"))
                        return self._json(job.state())
                    m = re.fullmatch(r"/api/runs/([0-9a-f]{12})/ai", path)
                    if m:
                        runs.load_info(m.group(1))
                        return self._json(jobs.start_ai(m.group(1), body.get("provider")).state())
                    m = re.fullmatch(r"/api/jobs/([0-9a-f]{12})/cancel", path)
                    if m:
                        jobs.get(m.group(1)).cancel_requested = True
                        return self._json({"ok": True})
                    m = re.fullmatch(r"/api/runs/([0-9a-f]{12})/export", path)
                    if m:
                        source = runs.report_path(m.group(1))
                        target = app.dialogs.save_file(f"log-report-{m.group(1)}.html")
                        if not target:
                            return self._json({"saved": None})
                        shutil.copyfile(source, target)
                        return self._json({"saved": target})
                    m = re.fullmatch(r"/api/runs/([0-9a-f]{12})/open", path)
                    if m:
                        webbrowser.open(runs.report_path(m.group(1)).resolve().as_uri())
                        return self._json({"ok": True})
                    return self._fail("Not found", 404)
                except KeyError:
                    return self._fail("That item no longer exists.", 404)
                except (ValueError, OSError) as exc:
                    return self._fail(str(exc))

        return Handler
