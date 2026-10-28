import json
import time
import urllib.error
import urllib.request

import pytest

from loganalyser.desktop.server import App
from loganalyser.samples import generate


@pytest.fixture()
def app():
    server = App()
    server.serve_in_background()
    yield server
    server.close()


def call(app, path, method="GET", body=None, token=True, host=None, raw=None):
    url = f"http://127.0.0.1:{app.port}{path}"
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("X-Token", app.token)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            text = res.read().decode()
            return res.status, (json.loads(text) if res.headers.get_content_type() == "application/json" else text)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_requests_need_the_token_and_a_local_host(app):
    assert call(app, "/api/state", token=False)[0] == 403
    assert call(app, "/api/state", host="evil.example:80")[0] == 403
    status, page = call(app, f"/?t={app.token}", token=False)
    assert status == 200 and app.token in page and "Find out why it broke" in page


def test_full_analysis_through_the_app(app, tmp_path):
    paths = generate(tmp_path / "logs")
    status, job = call(app, "/api/analyse", "POST", {"sources": [str(tmp_path / "logs" / "incident")],
                                                      "baseline": [str(tmp_path / "logs" / "baseline")], "ai": False})
    assert status == 200
    for _ in range(300):
        _, state = call(app, f"/api/jobs/{job['id']}")
        if state["finished"]:
            break
        time.sleep(0.1)
    assert state["error"] is None and state["runId"]
    assert "ai" in state["skipped"] and state["filesDone"] == len(paths["incident"]) + len(paths["baseline"])

    status, page = call(app, f"/report/{state['runId']}")
    assert status == 200 and "Database connection pool exhausted" in page
    _, st = call(app, "/api/state")
    assert st["history"][0]["title"] == "Database connection pool exhausted"
    assert call(app, f"/api/runs/{state['runId']}", "DELETE")[0] == 200
    assert call(app, "/api/state")[1]["history"] == []


def test_ai_with_missing_setup_is_skipped_with_a_reason(app, tmp_path):
    generate(tmp_path / "logs")
    _, job = call(app, "/api/analyse", "POST", {"sources": [str(tmp_path / "logs" / "incident")], "ai": True,
                                               "provider": "openai"})
    for _ in range(300):
        _, state = call(app, f"/api/jobs/{job['id']}")
        if state["finished"]:
            break
        time.sleep(0.1)
    assert state["runId"] and "AI step skipped" in state["warning"]


def test_missing_input_is_explained(app):
    status, body = call(app, "/api/analyse", "POST", {"sources": []})
    assert status == 400 and "Choose a folder" in body


def test_settings_save_keeps_keys_out_of_responses(app):
    _, saved = call(app, "/api/settings", "POST", {"active": "gemini", "providers": {"gemini": {"api_key": "g-secret", "model": "x"}}})
    assert saved["active"] == "gemini" and saved["providers"]["gemini"]["has_key"]
    assert "g-secret" not in json.dumps(saved)
    # A blank key field keeps the saved key.
    _, again = call(app, "/api/settings", "POST", {"providers": {"gemini": {"api_key": "", "model": "y"}}})
    assert again["providers"]["gemini"]["has_key"] and again["providers"]["gemini"]["model"] == "y"


def test_uploads_cannot_escape_their_folder(app):
    status, body = call(app, "/api/upload?batch=0123456789abcdef&name=../../evil.log", "POST", raw=b"x")
    assert status == 200
    folder = body["folder"]
    assert (app.uploads / "0123456789abcdef" / "evil.log").read_bytes() == b"x"
    assert folder.startswith(str(app.uploads))
    assert call(app, "/api/upload?batch=nothex&name=a.log", "POST", raw=b"x")[0] == 400
