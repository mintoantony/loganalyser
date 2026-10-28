"""Send one request to the configured LLM and get JSON back.

Claude goes through the official ``anthropic`` SDK. The other providers speak
one of three plain HTTP formats (OpenAI-style chat completions, Gemini, Ollama),
so they need nothing beyond the standard library. Every provider is asked for
the same JSON schema, so the rest of the app never needs to know which one
answered.
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace

from .settings import ProviderConfig


class LLMError(Exception):
    """A failure the person can act on; the message says what to do."""


def complete_json(cfg: ProviderConfig, system: str, user: str, schema: dict) -> tuple[dict, dict]:
    """Return (parsed JSON answer, details such as model and token use)."""
    cfg = cfg.resolved()
    problems = cfg.problems()
    if problems:
        raise LLMError(" ".join(problems))
    started = time.monotonic()
    wire = cfg.spec["wire"]
    if wire == "anthropic":
        text, meta = _anthropic(cfg, system, user, schema)
    elif wire == "gemini":
        text, meta = _gemini(cfg, system, user, schema)
    elif wire == "ollama":
        text, meta = _ollama(cfg, system, user, schema)
    else:
        text, meta = _openai_style(cfg, system, user, schema)
    meta["seconds"] = round(time.monotonic() - started, 1)
    return parse_json(text), meta


def list_models(cfg: ProviderConfig) -> list[str]:
    cfg = cfg.resolved()
    wire = cfg.spec["wire"]
    if wire == "anthropic":
        client = _anthropic_client(cfg)
        anthropic = _import_anthropic()
        try:
            return [m.id for m in client.models.list(limit=100)]
        except anthropic.AuthenticationError as exc:
            raise LLMError("The API key was rejected. Check it in Settings.") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError("Could not reach the Anthropic API. Check your internet connection or proxy.") from exc
    if wire == "gemini":
        data = _http("GET", f"{cfg.base_url}/models?pageSize=200", cfg, headers={"x-goog-api-key": cfg.api_key})
        return sorted(m["name"].removeprefix("models/") for m in data.get("models", [])
                      if "generateContent" in m.get("supportedGenerationMethods", []))
    if wire == "ollama":
        data = _http("GET", f"{cfg.base_url}/api/tags", cfg)
        return sorted(m["name"] for m in data.get("models", []))
    if wire == "azure":
        # Deployments are named by the person who created them; there is no reliable list call for keys.
        return [cfg.model] if cfg.model else []
    data = _http("GET", f"{cfg.base_url}/models", cfg, headers=_bearer(cfg))
    return sorted(m["id"] for m in data.get("data", []) if m.get("id"))


def test_connection(cfg: ProviderConfig) -> dict:
    """Send a tiny request and report how it went."""
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
              "additionalProperties": False}
    answer, meta = complete_json(replace(cfg, effort="low"), "Reply with JSON only.", 'Return {"ok": true}.', schema)
    return {"ok": bool(answer.get("ok", True)), **meta}


# --------------------------------------------------------------------- Claude
def _import_anthropic():
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - the app bundles it
        raise LLMError("The Claude provider needs the anthropic package: pip install anthropic") from exc
    return anthropic


def _anthropic_client(cfg: ProviderConfig):
    anthropic = _import_anthropic()
    kwargs = {"api_key": cfg.api_key, "timeout": cfg.timeout, "max_retries": 2}
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    return anthropic.Anthropic(**kwargs)


def _anthropic(cfg: ProviderConfig, system: str, user: str, schema: dict) -> tuple[str, dict]:
    anthropic = _import_anthropic()
    client = _anthropic_client(cfg)
    try:
        # Streaming keeps a long evidence pack clear of HTTP timeouts. The server-side fallback
        # re-runs the request on Anthropic's recommended model if a safety check declines it.
        with client.beta.messages.stream(
            model=cfg.model,
            max_tokens=32000,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": cfg.effort, "format": {"type": "json_schema", "schema": schema}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        ) as stream:
            message = stream.get_final_message()
    except anthropic.AuthenticationError as exc:
        raise LLMError("The Anthropic API key was rejected. Check it in Settings.") from exc
    except anthropic.PermissionDeniedError as exc:
        raise LLMError(f"This API key cannot use {cfg.model}: {exc.message}") from exc
    except anthropic.NotFoundError as exc:
        raise LLMError(f"Model {cfg.model} was not found. Pick another in Settings.") from exc
    except anthropic.RateLimitError as exc:
        raise LLMError("Anthropic is rate-limiting this key. Wait a minute and try again.") from exc
    except anthropic.BadRequestError as exc:
        raise LLMError(f"Anthropic rejected the request: {exc.message}") from exc
    except anthropic.APIStatusError as exc:
        raise LLMError(f"Anthropic returned an error ({exc.status_code}). Try again shortly.") from exc
    except anthropic.APIConnectionError as exc:
        raise LLMError("Could not reach the Anthropic API. Check your internet connection or proxy.") from exc

    if message.stop_reason == "refusal":
        details = getattr(message, "stop_details", None)
        reason = getattr(details, "explanation", None) or "no reason given"
        raise LLMError(f"Claude declined to analyse these logs ({reason}).")
    if message.stop_reason == "max_tokens":
        raise LLMError("Claude's answer was cut off. Send fewer lines (Settings, Privacy) and try again.")
    text = "".join(block.text for block in message.content if block.type == "text")
    usage = message.usage
    return text, {"model": message.model, "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens}


# ----------------------------------------------------------- OpenAI and Azure
def _bearer(cfg: ProviderConfig) -> dict:
    headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
    if cfg.provider == "openrouter":
        headers.update({"HTTP-Referer": "https://github.com/loganalyser", "X-Title": "LogAnalyser"})
    return headers


def _openai_style(cfg: ProviderConfig, system: str, user: str, schema: dict) -> tuple[str, dict]:
    if cfg.provider == "azure":
        if cfg.api_version.lower() == "v1":
            url = f"{cfg.base_url}/openai/v1/chat/completions"
        else:
            deployment = urllib.parse.quote(cfg.model, safe="")
            url = (f"{cfg.base_url}/openai/deployments/{deployment}/chat/completions"
                   f"?api-version={urllib.parse.quote(cfg.api_version)}")
        headers = {"api-key": cfg.api_key}
    else:
        url = f"{cfg.base_url}/chat/completions"
        headers = _bearer(cfg)
    base = {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if not (cfg.provider == "azure" and cfg.api_version.lower() != "v1"):
        base["model"] = cfg.model

    # Not every server supports strict JSON schemas; step down to JSON mode, then to plain text.
    formats = [
        {"type": "json_schema", "json_schema": {"name": "log_analysis", "schema": schema, "strict": True}},
        {"type": "json_object"},
        None,
    ]
    last_error: LLMError | None = None
    for fmt in formats:
        body = dict(base)
        if fmt:
            body["response_format"] = fmt
        try:
            data = _http("POST", url, cfg, body=body, headers=headers)
        except _BadRequest as exc:
            last_error = LLMError(f"{cfg.label} rejected the request: {exc}")
            continue
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        if message.get("refusal"):
            raise LLMError(f"The model declined to analyse these logs: {message['refusal']}")
        if choice.get("finish_reason") == "length":
            raise LLMError("The model's answer was cut off. Send fewer lines (Settings, Privacy) or pick a larger model.")
        usage = data.get("usage") or {}
        return message.get("content") or "", {"model": data.get("model") or cfg.model,
                                              "input_tokens": usage.get("prompt_tokens"),
                                              "output_tokens": usage.get("completion_tokens")}
    raise last_error or LLMError(f"{cfg.label} did not answer.")


# --------------------------------------------------------------------- Gemini
def _gemini(cfg: ProviderConfig, system: str, user: str, schema: dict) -> tuple[str, dict]:
    model = cfg.model.removeprefix("models/")
    url = f"{cfg.base_url}/models/{urllib.parse.quote(model, safe='.-_')}:generateContent"
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema},
    }
    headers = {"x-goog-api-key": cfg.api_key}
    try:
        data = _http("POST", url, cfg, body=body, headers=headers)
    except _BadRequest:
        # Older models do not take a schema; JSON mode plus the schema in the prompt still works.
        body["generationConfig"] = {"responseMimeType": "application/json"}
        data = _http("POST", url, cfg, body=body, headers=headers)
    candidates = data.get("candidates") or []
    if not candidates:
        reason = (data.get("promptFeedback") or {}).get("blockReason", "no answer")
        raise LLMError(f"Gemini did not answer ({reason}).")
    candidate = candidates[0]
    if candidate.get("finishReason") == "MAX_TOKENS":
        raise LLMError("Gemini's answer was cut off. Send fewer lines (Settings, Privacy) and try again.")
    text = "".join(part.get("text", "") for part in (candidate.get("content") or {}).get("parts", []))
    usage = data.get("usageMetadata") or {}
    return text, {"model": data.get("modelVersion") or model, "input_tokens": usage.get("promptTokenCount"),
                  "output_tokens": usage.get("candidatesTokenCount")}


# --------------------------------------------------------------------- Ollama
def _ollama(cfg: ProviderConfig, system: str, user: str, schema: dict) -> tuple[str, dict]:
    body = {
        "model": cfg.model, "stream": False, "format": schema,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        # Ollama's default context is small; the evidence pack needs room.
        "options": {"num_ctx": 32768},
    }
    try:
        data = _http("POST", f"{cfg.base_url}/api/chat", cfg, body=body)
    except _BadRequest:
        body["format"] = "json"
        data = _http("POST", f"{cfg.base_url}/api/chat", cfg, body=body)
    return (data.get("message") or {}).get("content", ""), {
        "model": data.get("model") or cfg.model, "input_tokens": data.get("prompt_eval_count"),
        "output_tokens": data.get("eval_count")}


# ----------------------------------------------------------------------- HTTP
class _BadRequest(Exception):
    pass


def _http(method: str, url: str, cfg: ProviderConfig, body: dict | None = None,
          headers: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=cfg.timeout) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = _error_text(exc)
        if exc.code in (400, 422):
            raise _BadRequest(detail) from exc
        if exc.code in (401, 403):
            raise LLMError(f"{cfg.label} rejected the API key ({exc.code}). Check it in Settings. {detail}".strip()) from exc
        if exc.code == 404:
            raise LLMError(f"{cfg.label} could not find that model or endpoint. Check the model name and URL. {detail}".strip()) from exc
        if exc.code == 429:
            raise LLMError(f"{cfg.label} is rate-limiting this key. Wait a minute and try again.") from exc
        raise LLMError(f"{cfg.label} returned an error ({exc.code}). {detail}".strip()) from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ConnectionRefusedError) or "refused" in str(reason).lower():
            if cfg.provider == "ollama":
                raise LLMError(f"Ollama is not running at {cfg.base_url}. Start it with `ollama serve`.") from exc
            raise LLMError(f"Nothing is answering at {cfg.base_url}. Check the URL.") from exc
        raise LLMError(f"Could not reach {cfg.label} at {cfg.base_url}: {reason}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise LLMError(f"{cfg.label} took longer than {cfg.timeout:.0f}s to answer. "
                       "Try a faster model or send fewer lines.") from exc
    except ValueError as exc:
        raise LLMError(f"{cfg.label} sent back something that is not JSON.") from exc


def _error_text(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(exc.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - the body is only used for a hint
        return ""
    err = payload.get("error", payload)
    if isinstance(err, dict):
        return str(err.get("message") or err.get("error") or "")[:300]
    return str(err)[:300]


def parse_json(text: str) -> dict:
    """Read the model's answer as JSON, tolerating code fences or a sentence around it."""
    text = (text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    try:
        value = json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise LLMError("The model did not return the analysis in the expected format. Try again or pick another model.")
        try:
            value = json.loads(text[start:end + 1])
        except ValueError as exc:
            raise LLMError("The model's answer was not valid JSON. Try again or pick another model.") from exc
    if not isinstance(value, dict):
        raise LLMError("The model's answer was not in the expected format.")
    return value
