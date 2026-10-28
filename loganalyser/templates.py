"""Group similar log messages into templates ("patterns").

Variable parts (numbers, IDs, IPs, paths, durations) are masked first, then a
small Drain-style tree groups messages of the same length and leading token
and merges them when most tokens agree. "Connection to 10.0.0.4 failed after
3 retries" and "Connection to 10.0.0.9 failed after 5 retries" become one
pattern: "Connection to <IP> failed after <NUM> retries".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_MASKS: list[tuple[re.Pattern[str], object]] = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\bhttps?://[^\s\"'<>]+"), "<URL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{12,}\b"), "<HEX>"),
    # Paths and routes keep their shape; only segments holding a number or ID become {id}.
    (re.compile(r"(?<![\w<])(?:/[\w.@%+-]+){2,}/?"),
     lambda m: "/".join("{id}" if re.search(r"\d", seg) else seg for seg in m.group(0).split("/"))),
    (re.compile(r"\b[A-Za-z]:\\[^\s\"']+"), "<PATH>"),
    (re.compile(r"\b(?=[A-Za-z_-]*\d)[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*-[A-Za-z0-9_-]+\b"), "<ID>"),
    # Random tokens such as session or circuit IDs: 20+ characters mixing capitals, small letters and digits.
    (re.compile(r"(?<![\w<])(?=[\w-]*\d)(?=[\w-]*[A-Z])(?=[\w-]*[a-z])[\w-]{20,}(?![\w>])"), "<ID>"),
    (re.compile(r"(?<![\w.<])[-+]?\d+(?:\.\d+)?(?:ms|s|us|µs|ns|m|h|kb|mb|gb|KB|MB|GB|B|%)?(?![\w>])"), "<NUM>"),
]
_TOKEN_SPLIT = re.compile(r"\s+")
_PLACEHOLDER = re.compile(r"^<[A-Z]+>[^\s]*$|^<\*>$")
_MAX_TOKENS = 48


def mask(message: str) -> str:
    text = message
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


def tokenize(message: str, masked: bool = False) -> list[str]:
    text = message if masked else mask(message)
    tokens = [t for t in _TOKEN_SPLIT.split(text.strip()) if t]
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS] + ["<...>"]
    return tokens


@dataclass(slots=True)
class Template:
    id: int
    tokens: list[str]
    count: int = 0
    record_ids: list[int] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(self.tokens)


def _similarity(template: list[str], tokens: list[str]) -> tuple[float, int]:
    same = 0
    wildcards = 0
    for a, b in zip(template, tokens):
        if a == "<*>":
            wildcards += 1
        elif a == b:
            same += 1
    return same / len(tokens), wildcards


class TemplateMiner:
    """Online Drain-like clustering. Call add() per message, read templates afterwards."""

    def __init__(self, similarity: float = 0.55):
        self.similarity = similarity
        self.templates: list[Template] = []
        self._groups: dict[tuple[int, str, str], list[Template]] = {}
        self._exact: dict[str, Template] = {}

    def add(self, message: str, record_index: int, masked: bool = False, source: str = "") -> Template:
        """Add one message. ``masked=True`` means it is already a pattern key and is used as is.

        ``source`` (the logger) keeps messages from different code apart: "Failed to write thumbnail <path>"
        in one service and "Failed to enqueue thumbnail job" in another agree on 3 of 5 words, but they are
        different failures. Copies of one service share a logger name, so their messages still merge.
        """
        tokens = tokenize(message, masked) or ["<empty>"]
        if masked:
            # Pattern keys are exact: "GET /x -> 200" and "GET /x -> 503" must stay apart.
            exact = self._exact.get(message)
            if exact is None:
                exact = Template(id=len(self.templates), tokens=tokens)
                self.templates.append(exact)
                self._exact[message] = exact
            exact.count += 1
            exact.record_ids.append(record_index)
            return exact
        first = tokens[0] if not _PLACEHOLDER.match(tokens[0]) else "<*>"
        key = (len(tokens), first, source)
        group = self._groups.setdefault(key, [])

        best: Template | None = None
        best_score = -1.0
        best_wild = -1
        for candidate in group:
            score, wild = _similarity(candidate.tokens, tokens)
            if score > best_score or (score == best_score and wild > best_wild):
                best, best_score, best_wild = candidate, score, wild

        # Short messages need to agree almost fully to merge.
        threshold = self.similarity if len(tokens) > 3 else 0.67
        if best is not None and best_score >= threshold:
            best.tokens = [a if a == b else "<*>" for a, b in zip(best.tokens, tokens)]
        else:
            best = Template(id=len(self.templates), tokens=tokens)
            self.templates.append(best)
            group.append(best)
        best.count += 1
        best.record_ids.append(record_index)
        return best
