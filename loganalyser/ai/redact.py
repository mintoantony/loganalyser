"""Hide personal data and secrets in log text before it leaves the machine.

Request and trace IDs are kept on purpose: they are what links lines across
files, and the LLM needs them to follow a request.
"""

from __future__ import annotations

import re

_RULES: list[tuple[re.Pattern[str], str]] = [
    # Secrets first, so later rules cannot split them.
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "<jwt>"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 <secret>"),
    (re.compile(r"\b(?:sk|pk|rk)-(?:[A-Za-z0-9_-]{2,}-)?[A-Za-z0-9_-]{16,}"), "<api-key>"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<aws-key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "<token>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "<token>"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|auth|credentials?)"
                r"(\s*[=:]\s*|\"\s*:\s*\")([^\s\"',;&]{3,})"), r"\1\2<secret>"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@"), r"\1<user>:<secret>@"),
    # Personal data.
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<email>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"), "<ip>"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<card-or-account>"),
    (re.compile(r"(?i)([A-Z]:\\Users\\|/Users/|/home/)[^\\/\s]+"), r"\1<user>"),
]


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
