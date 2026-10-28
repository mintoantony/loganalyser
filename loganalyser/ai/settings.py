"""Saved LLM settings, shared by the desktop app and the command line.

Settings live in a JSON file in the user's app-data folder. API keys go to the
operating system's keychain (Windows Credential Manager, macOS Keychain) when
the ``keyring`` package is available, and fall back to the settings file
otherwise, readable by the current user only.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

_KEYRING_SERVICE = "LogAnalyser"

# Provider id -> how it is shown and what it needs. "wire" is the request format.
PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "label": "Claude (Anthropic API)", "wire": "anthropic", "needs_key": True,
        "base_url": "", "model": "claude-opus-5-5", "key_env": "ANTHROPIC_API_KEY",
        "hint": "Key from console.anthropic.com. Uses Claude Opus 5.5 unless you pick another model.",
    },
    "openai": {
        "label": "OpenAI", "wire": "openai", "needs_key": True,
        "base_url": "https://api.openai.com/v1", "model": "", "key_env": "OPENAI_API_KEY",
        "hint": "Key from platform.openai.com. Load the list to pick a model.",
    },
    "gemini": {
        "label": "Google Gemini", "wire": "gemini", "needs_key": True,
        "base_url": "https://generativelanguage.googleapis.com/v1beta", "model": "", "key_env": "GEMINI_API_KEY",
        "hint": "Key from aistudio.google.com. Load the list to pick a model.",
    },
    "azure": {
        "label": "Microsoft Azure AI Foundry", "wire": "azure", "needs_key": True,
        "base_url": "", "model": "", "key_env": "AZURE_OPENAI_API_KEY", "api_version": "2024-10-21",
        "hint": "Endpoint such as https://<resource>.openai.azure.com, and the name of your model deployment.",
    },
    "openrouter": {
        "label": "OpenRouter", "wire": "openai", "needs_key": True,
        "base_url": "https://openrouter.ai/api/v1", "model": "", "key_env": "OPENROUTER_API_KEY",
        "hint": "Key from openrouter.ai. Any model it offers, for example anthropic/… or google/….",
    },
    "ollama": {
        "label": "Ollama (on your machine)", "wire": "ollama", "needs_key": False,
        "base_url": "http://localhost:11434", "model": "", "key_env": "",
        "hint": "Runs locally, nothing leaves your machine. Start Ollama, then load the list of installed models.",
    },
    "custom": {
        "label": "Other OpenAI-compatible server", "wire": "openai", "needs_key": False,
        "base_url": "http://localhost:1234/v1", "model": "", "key_env": "",
        "hint": "LM Studio, vLLM, LiteLLM and similar. Give the base URL ending in /v1.",
    },
}


@dataclass
class ProviderConfig:
    provider: str = "anthropic"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    api_version: str = ""          # Azure only
    effort: str = "high"           # Claude only: low | medium | high | xhigh | max
    timeout: float = 0.0           # seconds; 0 means the provider's default

    @property
    def spec(self) -> dict:
        return PROVIDERS[self.provider]

    @property
    def label(self) -> str:
        return self.spec["label"]

    def resolved(self) -> "ProviderConfig":
        """Fill blanks from provider defaults and the provider's environment variable."""
        spec = self.spec
        return ProviderConfig(
            provider=self.provider,
            model=self.model or spec.get("model", ""),
            base_url=(self.base_url or spec.get("base_url", "")).rstrip("/"),
            api_key=self.api_key or (os.environ.get(spec["key_env"], "") if spec.get("key_env") else ""),
            api_version=self.api_version or spec.get("api_version", ""),
            effort=self.effort or "high",
            # Models running on a laptop can take many minutes over a large evidence pack.
            timeout=self.timeout or (900.0 if self.provider in ("ollama", "custom") else 300.0),
        )

    def problems(self) -> list[str]:
        """What is missing before this provider can be called, in plain words."""
        cfg = self.resolved()
        issues = []
        if cfg.spec["needs_key"] and not cfg.api_key:
            issues.append(f"Add an API key for {cfg.label}.")
        if not cfg.model:
            issues.append("Choose a model." if cfg.provider != "azure" else "Give the deployment name.")
        if cfg.provider in ("azure", "custom", "ollama") and not cfg.base_url:
            issues.append("Give the endpoint URL.")
        return issues


@dataclass
class Privacy:
    redact: bool = True       # hide emails, IPs, tokens, secrets and user names before sending
    max_lines: int = 300      # most log lines sent as evidence


@dataclass
class Settings:
    active: str = "anthropic"
    ai_enabled: bool = False
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    privacy: Privacy = field(default_factory=Privacy)

    def provider(self, name: str | None = None) -> ProviderConfig:
        name = name or self.active
        if name not in PROVIDERS:
            raise ValueError(f"Unknown provider {name!r}. Choose one of: {', '.join(PROVIDERS)}.")
        return self.providers.get(name) or ProviderConfig(provider=name)

    # ------------------------------------------------------------ storage
    @staticmethod
    def folder() -> Path:
        override = os.environ.get("LOGANALYSER_HOME")
        if override:
            return Path(override)
        if sys.platform == "win32":
            return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "LogAnalyser"
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "LogAnalyser"
        return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "loganalyser"

    @classmethod
    def load(cls) -> "Settings":
        path = cls.folder() / "settings.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {f.name for f in fields(ProviderConfig)}
        providers = {}
        for name, data in (raw.get("providers") or {}).items():
            if name in PROVIDERS and isinstance(data, dict):
                cfg = ProviderConfig(**{k: v for k, v in data.items() if k in known})
                cfg.provider = name
                if not cfg.api_key:
                    cfg.api_key = _keyring_get(name)
                providers[name] = cfg
        privacy = Privacy(**{k: v for k, v in (raw.get("privacy") or {}).items() if k in ("redact", "max_lines")})
        active = raw.get("active") if raw.get("active") in PROVIDERS else "anthropic"
        return cls(active=active, ai_enabled=bool(raw.get("ai_enabled")), providers=providers, privacy=privacy)

    def save(self) -> None:
        folder = self.folder()
        folder.mkdir(parents=True, exist_ok=True)
        providers = {}
        for name, cfg in self.providers.items():
            data = asdict(cfg)
            if cfg.api_key and _keyring_set(name, cfg.api_key):
                data["api_key"] = ""
            elif not cfg.api_key:
                _keyring_delete(name)
            providers[name] = data
        payload = {"active": self.active, "ai_enabled": self.ai_enabled,
                   "providers": providers, "privacy": asdict(self.privacy)}
        path = folder / "settings.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(path)

    def public(self) -> dict:
        """Settings for the app's screens: keys are never sent back, only whether one is set."""
        out = {"active": self.active, "ai_enabled": self.ai_enabled, "privacy": asdict(self.privacy),
               "providers": {}, "catalog": PROVIDERS}
        for name in PROVIDERS:
            cfg = self.provider(name)
            data = asdict(cfg)
            data["api_key"] = ""
            data["has_key"] = bool(cfg.resolved().api_key)
            data["key_from_env"] = bool(not cfg.api_key and cfg.resolved().api_key)
            out["providers"][name] = data
        return out


def _keyring():
    if os.environ.get("LOGANALYSER_NO_KEYRING"):
        return None
    try:
        import keyring  # optional dependency

        return keyring
    except Exception:  # noqa: BLE001 - any import problem means "no keychain"
        return None


def _keyring_get(name: str) -> str:
    kr = _keyring()
    if not kr:
        return ""
    try:
        return kr.get_password(_KEYRING_SERVICE, name) or ""
    except Exception:  # noqa: BLE001 - a broken keychain must not stop the app
        return ""


def _keyring_set(name: str, secret: str) -> bool:
    kr = _keyring()
    if not kr:
        return False
    try:
        kr.set_password(_KEYRING_SERVICE, name, secret)
        return True
    except Exception:  # noqa: BLE001
        return False


def _keyring_delete(name: str) -> None:
    kr = _keyring()
    if not kr:
        return
    try:
        kr.delete_password(_KEYRING_SERVICE, name)
    except Exception:  # noqa: BLE001
        pass
