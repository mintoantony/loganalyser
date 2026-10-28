import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from loganalyser.ai import ProviderConfig, Settings, run_ai
from loganalyser.ai import providers
from loganalyser.ai.advisor import SCHEMA, build_evidence, normalise
from loganalyser.ai.providers import LLMError, complete_json, parse_json
from loganalyser.ai.redact import redact
from loganalyser.analysis import analyse
from loganalyser.parser import parse_file
from loganalyser.samples import generate


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    paths = generate(tmp_path_factory.mktemp("demo"))
    return analyse([parse_file(p) for p in paths["incident"]], [parse_file(p) for p in paths["baseline"]])


def good_answer(line_ref: str) -> dict:
    return {
        "summary": "A batch job held every database connection.",
        "root_cause": {"title": "Database connection pool exhausted", "category": "Database", "confidence": "high",
                       "confidence_pct": 88, "explanation": "The pool ran dry first.", "agrees_with_engine": True,
                       "engine_candidate": "C1", "evidence": [{"line": line_ref, "why": "pool at capacity"},
                                                              {"line": "L99999999", "why": "made up"}]},
        "contributing_factors": [], "alternatives": [{"title": "Slow queries", "why_less_likely": "Started later"}],
        "timeline": [{"time": "09:28:12", "event": "Pool ran dry", "line": line_ref}], "impact": "Orders failed.",
        "recommended_actions": [{"action": "Stop the export job", "why": "Frees connections", "when": "now"}],
        "checks": ["Confirm the job schedule"], "log_matches": [],
    }


# ------------------------------------------------------------------- redaction
def test_redaction_hides_personal_data_and_secrets_but_keeps_ids():
    text = ("user bob@example.com from 10.1.2.3 Authorization: Bearer abcdefghijklmnop1234 "
            "password=hunter22 key sk-ant-api03-abcdefghijklmnopqrstuv path C:\\Users\\alice\\app.log traceId=4bf92f3577b34da6")
    out = redact(text)
    for secret in ("bob@example.com", "10.1.2.3", "abcdefghijklmnop1234", "hunter22", "sk-ant-api03", "alice"):
        assert secret not in out
    assert "traceId=4bf92f3577b34da6" in out


# ---------------------------------------------------------------- evidence pack
def test_evidence_pack_cites_lines_and_hides_emails(demo):
    text, chosen = build_evidence(demo, max_lines=50, hide_personal_data=True)
    assert "C1. Database connection pool exhausted" in text
    assert 0 < len(chosen) <= 50
    assert f"L{chosen[0]} |" in text
    assert "@example.com" not in text
    assert "Job nightly-export started" in text


def test_normalise_keeps_only_real_lines_and_fixes_values():
    answer = good_answer("L5")
    answer["root_cause"]["confidence_pct"] = 400
    answer["recommended_actions"][0]["when"] = "yesterday"
    out = normalise(answer, {5})
    assert [e["line"] for e in out["rootCause"]["evidence"]] == [5]
    assert out["rootCause"]["confidencePct"] == 100
    assert out["rootCause"]["engineCandidate"] == 1
    assert out["actions"][0]["when"] == "soon"


def test_parse_json_tolerates_fences_and_chatter():
    assert parse_json('Sure!\n```json\n{"ok": true}\n```') == {"ok": True}
    assert parse_json('Here it is: {"ok": 1} hope that helps') == {"ok": 1}
    with pytest.raises(LLMError):
        parse_json("no json here")


# -------------------------------------------------------- HTTP providers (fake)
class FakeServer:
    """A local stand-in for OpenAI-style, Azure, Gemini and Ollama endpoints."""

    def __init__(self, reply, status_for=None):
        self.requests = []
        self.reply = reply
        self.status_for = status_for or (lambda body: 200)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                headers = {k.lower(): v for k, v in self.headers.items()}  # header names are case-insensitive
                server.requests.append({"path": self.path, "headers": headers, "body": body})
                status = server.status_for(body)
                payload = server.reply(self.path, body) if status == 200 else {"error": {"message": "nope"}}
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()


def openai_reply(content):
    return lambda path, body: {"model": body.get("model", "dep"), "choices": [{"message": {"content": content},
                                                                               "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


def test_openai_style_request_uses_strict_schema_and_bearer_key():
    fake = FakeServer(openai_reply('{"ok": true}'))
    try:
        cfg = ProviderConfig(provider="openrouter", model="some/model", base_url=fake.url, api_key="k-123")
        answer, meta = complete_json(cfg, "sys", "user", {"type": "object"})
    finally:
        fake.close()
    req = fake.requests[0]
    assert answer == {"ok": True} and meta["input_tokens"] == 10
    assert req["path"] == "/chat/completions"
    assert req["headers"]["authorization"] == "Bearer k-123"
    assert req["body"]["response_format"]["type"] == "json_schema"
    assert req["body"]["model"] == "some/model"


def test_openai_style_steps_down_when_schemas_are_not_supported():
    fake = FakeServer(openai_reply('{"ok": true}'), status_for=lambda b: 400 if "response_format" in b and
                      b["response_format"]["type"] == "json_schema" else 200)
    try:
        answer, _ = complete_json(ProviderConfig(provider="custom", model="m", base_url=fake.url), "s", "u", {})
    finally:
        fake.close()
    assert answer == {"ok": True}
    assert [r["body"].get("response_format", {}).get("type") for r in fake.requests] == ["json_schema", "json_object"]


def test_azure_uses_deployment_url_and_api_key_header():
    fake = FakeServer(openai_reply('{"ok": true}'))
    try:
        cfg = ProviderConfig(provider="azure", model="my-dep", base_url=fake.url, api_key="az", api_version="2024-10-21")
        complete_json(cfg, "s", "u", {})
    finally:
        fake.close()
    req = fake.requests[0]
    assert req["path"] == "/openai/deployments/my-dep/chat/completions?api-version=2024-10-21"
    assert req["headers"]["api-key"] == "az"
    assert "model" not in req["body"]


def test_gemini_request_shape():
    fake = FakeServer(lambda path, body: {"candidates": [{"content": {"parts": [{"text": '{"ok": true}'}]},
                                                          "finishReason": "STOP"}], "modelVersion": "g"})
    try:
        cfg = ProviderConfig(provider="gemini", model="gemini-x", base_url=fake.url, api_key="g-key")
        answer, _ = complete_json(cfg, "sys", "user", {"type": "object"})
    finally:
        fake.close()
    req = fake.requests[0]
    assert answer == {"ok": True}
    assert req["path"] == "/models/gemini-x:generateContent"
    assert req["headers"]["x-goog-api-key"] == "g-key"
    assert req["body"]["generationConfig"]["responseMimeType"] == "application/json"


def test_ollama_request_shape():
    fake = FakeServer(lambda path, body: {"model": body["model"], "message": {"content": '{"ok": true}'}})
    try:
        answer, _ = complete_json(ProviderConfig(provider="ollama", model="qwen", base_url=fake.url), "s", "u", {"type": "object"})
    finally:
        fake.close()
    assert answer == {"ok": True}
    assert fake.requests[0]["path"] == "/api/chat"
    assert fake.requests[0]["body"]["format"] == {"type": "object"}


def test_rejected_key_gives_a_plain_message():
    fake = FakeServer(openai_reply("{}"), status_for=lambda b: 401)
    try:
        with pytest.raises(LLMError, match="rejected the API key"):
            complete_json(ProviderConfig(provider="openai", model="m", base_url=fake.url, api_key="bad"), "s", "u", {})
    finally:
        fake.close()


def test_ollama_not_running_is_explained():
    with pytest.raises(LLMError, match="Ollama is not running"):
        complete_json(ProviderConfig(provider="ollama", model="m", base_url="http://127.0.0.1:9"), "s", "u", {})


def test_missing_key_is_reported_before_calling():
    with pytest.raises(LLMError, match="Add an API key"):
        complete_json(ProviderConfig(provider="openai", model="m"), "s", "u", {})


# ---------------------------------------------------------------- Claude (SDK)
class FakeStream:
    def __init__(self, message, calls, kwargs):
        self.message, self.calls, self.kwargs = message, calls, kwargs

    def __enter__(self):
        self.calls.append(self.kwargs)
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self.message


def fake_claude(monkeypatch, message):
    calls = []
    client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(
        stream=lambda **kwargs: FakeStream(message, calls, kwargs))))
    monkeypatch.setattr(providers, "_anthropic_client", lambda cfg: client)
    return calls


def claude_message(text, stop_reason="end_turn"):
    return SimpleNamespace(stop_reason=stop_reason, model="claude-opus-5-5", stop_details=None,
                           content=[SimpleNamespace(type="text", text=text)],
                           usage=SimpleNamespace(input_tokens=1200, output_tokens=300))


def test_claude_request_uses_schema_effort_and_fallback(monkeypatch):
    calls = fake_claude(monkeypatch, claude_message('{"ok": true}'))
    answer, meta = complete_json(ProviderConfig(provider="anthropic", api_key="sk-x"), "sys", "user", {"type": "object"})
    sent = calls[0]
    assert answer == {"ok": True} and meta["model"] == "claude-opus-5-5"
    assert sent["model"] == "claude-opus-5-5"
    assert sent["output_config"] == {"effort": "high", "format": {"type": "json_schema", "schema": {"type": "object"}}}
    assert sent["fallbacks"] == "default" and sent["betas"] == ["server-side-fallback-2026-07-01"]
    assert "thinking" not in sent and "temperature" not in sent


def test_claude_refusal_is_reported(monkeypatch):
    fake_claude(monkeypatch, claude_message("", stop_reason="refusal"))
    with pytest.raises(LLMError, match="declined"):
        complete_json(ProviderConfig(provider="anthropic", api_key="sk-x"), "s", "u", {})


# ------------------------------------------------------------------ end to end
def test_run_ai_adds_a_checked_second_opinion(demo, monkeypatch):
    result = json.loads(json.dumps(demo))
    _, chosen = build_evidence(result, 40)
    calls = fake_claude(monkeypatch, claude_message(json.dumps(good_answer(f"L{chosen[0]}"))))
    report = run_ai(result, ProviderConfig(provider="anthropic", api_key="sk-x"), max_lines=40)
    assert report["status"] == "ok" and result["ai"] is report
    rc = report["analysis"]["rootCause"]
    assert rc["title"] == "Database connection pool exhausted" and rc["agreesWithEngine"]
    assert [e["line"] for e in rc["evidence"]] == [chosen[0]]  # the made-up line was dropped
    assert report["linesSent"] == len(chosen) and report["redacted"]
    assert calls[0]["output_config"]["format"]["schema"] is SCHEMA


def test_run_ai_failure_keeps_the_analysis(demo):
    result = json.loads(json.dumps(demo))
    report = run_ai(result, ProviderConfig(provider="openai", model="m"))
    assert report["status"] == "error" and "API key" in report["error"]
    assert result["causes"]  # untouched


# -------------------------------------------------------------------- settings
def test_settings_round_trip_never_exposes_keys():
    settings = Settings.load()
    settings.active = "openrouter"
    settings.providers["openrouter"] = ProviderConfig(provider="openrouter", model="m", api_key="secret-key")
    settings.save()
    loaded = Settings.load()
    assert loaded.active == "openrouter" and loaded.provider().api_key == "secret-key"
    public = loaded.public()
    assert public["providers"]["openrouter"]["has_key"] is True
    assert "secret-key" not in json.dumps(public)
