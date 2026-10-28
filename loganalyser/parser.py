"""Turn raw log files into structured records.

The parser does not need to be told the format. For each line it looks for a
timestamp and a level near the start, understands JSON lines, syslog and
web-server access logs, and folds continuation lines (stack traces,
tracebacks) into the record that started them.
"""

from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

LEVELS = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]
LEVEL_RANK = {name: i for i, name in enumerate(LEVELS)}

_LEVEL_ALIASES = {
    "TRACE": "TRACE", "FINEST": "TRACE", "FINER": "TRACE", "VERBOSE": "TRACE",
    "DEBUG": "DEBUG", "DBG": "DEBUG", "FINE": "DEBUG",
    "INFO": "INFO", "INF": "INFO", "NOTICE": "INFO", "INFORMATION": "INFO", "LOG": "INFO",
    "WARN": "WARN", "WARNING": "WARN", "WRN": "WARN",
    "ERROR": "ERROR", "ERR": "ERROR", "EROR": "ERROR", "SEVERE": "ERROR",
    "FATAL": "FATAL", "CRITICAL": "FATAL", "CRIT": "FATAL", "EMERG": "FATAL",
    "ALERT": "FATAL", "PANIC": "FATAL",
}
# Single letters only count when they sit in their own brackets or columns, e.g. "E/" or "[E]".
_SHORT_LEVELS = {"T": "TRACE", "D": "DEBUG", "I": "INFO", "W": "WARN", "E": "ERROR", "F": "FATAL"}

_LEVEL_RE = re.compile(
    r"(?<![\w.-])\[?<?(" + "|".join(sorted(_LEVEL_ALIASES, key=len, reverse=True)) + r")>?\]?(?![\w-])",
    re.IGNORECASE,
)
_SHORT_LEVEL_RE = re.compile(r"^(?:\[([TDIWEF])\]|([TDIWEF])/)")

_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_TS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # 2024-03-05T10:42:01.123Z, 2024-03-05 10:42:01,123 +0100, 2024/03/05 10:42:01
    (re.compile(
        r"\[?(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:\s?Z|\s?[+-]\d{2}:?\d{2}|\s(?:UTC|GMT))?)\]?"
    ), "iso"),
    # 10/Oct/2023:13:55:36 +0000 (Apache / Nginx)
    (re.compile(r"\[(\d{2}/(?:" + _MONTHS + r")/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?)\]"), "clf"),
    # 5 Mar 2024 10:42:01.123 (Redis)
    (re.compile(r"(\d{1,2} (?:" + _MONTHS + r") \d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"), "dmy"),
    # Mar  5 10:42:01 (syslog, no year)
    (re.compile(r"((?:" + _MONTHS + r") {1,2}\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"), "syslog"),
    # 05-Mar-2024 10:42:01.123 (Tomcat)
    (re.compile(r"(\d{2}-(?:" + _MONTHS + r")-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"), "tomcat"),
    # 03/05/2024 10:42:01.123 +01:00: month first (US) or day first (UK, Serilog); decided per file
    (re.compile(r"(\d{1,2}/\d{1,2}/\d{4}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,7})?(?:\s?Z|\s?[+-]\d{2}:?\d{2}\b)?)"), "us"),
    # 10:42:01.123 (time only)
    (re.compile(r"^\[?(\d{2}:\d{2}:\d{2}[.,]\d{3,6})\]?"), "time"),
]

_ACCESS_RE = re.compile(
    r'^(?P<client>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?(?P<tail>.*)$'
)
_RESPONSE_TIME_RE = re.compile(r"^\s*(?:(?:rt|request_time|response_time)=)?([\d.]+)\b|\b(?:rt|request_time|response_time)=([\d.]+)")
_SPRING_PID_RE = re.compile(r"^\d+\s+---\s+")
# Redis: "1:M 28 Oct 2026 14:31:05.120 # message". The letter is the role and the mark the level:
# "." debug, "-" verbose, "*" notice, "#" warning.
_REDIS_HEAD_RE = re.compile(r"^(?P<pid>\d+):(?P<role>[XCSM]) $")
_REDIS_MARK_RE = re.compile(r"^\s*(?P<mark>[.*#-])\s+")
_SYSLOG_HEAD_RE = re.compile(r"^(?P<host>[\w.-]+) (?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?: ")
_THREAD_RE = re.compile(r"^\[(?P<thread>[^\]]{1,80})\]\s*")
# A logger is a dotted name ("com.shop.OrderService:" / "app.db -") or a single name before " - ".
_LOGGER_RE = re.compile(
    r"^(?:(?P<logger>[A-Za-z_$][\w$]*(?:\.[\w$-]+)+)\s*(?P<sep>-|:|\|)\s+|(?P<simple>[A-Za-z_][\w-]*)\s+-\s+)"
)
_PY_LOGGING_RE = re.compile(r"^(?P<level>[A-Z]+):(?P<logger>[\w.]+):(?P<msg>.*)$")

_CONTINUATION_RE = re.compile(
    r"^(?:\s+|at |Caused by:|Traceback |During handling|The above exception|"
    r"\.\.\. \d+ (?:more|common)|File \"|Suppressed:|\}|\]|---)"
)
_PY_EXC_LINE_RE = re.compile(r"^[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Warning)(?::|$)")

ID_PATTERNS = [
    re.compile(
        r"(?i)\b(?:trace|request|req|correlation|corr|txn|transaction|x-request|session|order|job)"
        r"[-_ ]?id\b[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9][\w.:-]{5,63})"
    ),
    re.compile(r"(?i)\btraceparent[=:]\s*\d{2}-([0-9a-f]{32})-"),
]
_JSON_ID_KEYS = ("trace_id", "traceId", "request_id", "requestId", "reqId", "req_id", "correlation_id",
                 "correlationId", "span_id", "txn_id", "order_id", "orderId", "session_id")

_JSON_TS_KEYS = ("@timestamp", "timestamp", "time", "ts", "datetime", "date", "eventTime", "t")
_JSON_LEVEL_KEYS = ("level", "severity", "lvl", "log.level", "loglevel", "levelname", "@l")
_JSON_MSG_KEYS = ("message", "msg", "@m", "@mt", "text", "log", "event")
_JSON_LOGGER_KEYS = ("logger", "logger_name", "name", "component", "service", "module", "source")
_JSON_ERR_KEYS = ("error", "err", "exception", "stack_trace", "stack", "stacktrace", "exc_info")

_ERROR_HINT_RE = re.compile(
    r"(?i)\b(exception|error|failed|failure|fatal|panic|refused|timed? ?out|denied|unable to|cannot|"
    r"could not|crash(?:ed)?|abort(?:ed)?|segfault|killed|unreachable|broken pipe)\b"
)
_WARN_HINT_RE = re.compile(r"(?i)\b(warn(?:ing)?|retry(?:ing)?|deprecated|slow|degraded|high|exceeded)\b")


@dataclass(slots=True)
class LogRecord:
    """One logical log event, possibly spanning several physical lines."""

    file: str
    line_no: int
    raw: str
    ts: float | None = None
    level: str = "INFO"
    level_inferred: bool = False
    logger: str = ""
    message: str = ""
    detail: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    fields: dict = field(default_factory=dict)
    template_id: int = -1

    @property
    def text(self) -> str:
        if not self.detail:
            return self.message
        return self.message + "\n" + "\n".join(self.detail)


@dataclass(slots=True)
class ParsedFile:
    path: str
    name: str
    records: list[LogRecord]
    line_count: int
    format: str
    timestamped: float  # share of records with a timestamp, 0..1


def normalise_level(token: str | None) -> str | None:
    if not token:
        return None
    return _LEVEL_ALIASES.get(token.strip("[]<>").upper())


def parse_timestamp(text: str, kind: str, default_year: int, day_first: bool = False) -> float | None:
    try:
        if kind == "iso":
            value = text.replace("/", "-").replace(",", ".").replace(" Z", "Z")
            value = re.sub(r"\s(?:UTC|GMT)$", "+00:00", value)
            value = re.sub(r"\s([+-]\d{2}:?\d{2})$", r"\1", value)
            # Trim fractions beyond microseconds, which fromisoformat rejects.
            value = re.sub(r"(\.\d{6})\d+", r"\1", value)
            dt = datetime.fromisoformat(value)
        elif kind == "clf":
            fmt = "%d/%b/%Y:%H:%M:%S %z" if " " in text else "%d/%b/%Y:%H:%M:%S"
            dt = datetime.strptime(text, fmt)
        elif kind == "syslog":
            base = re.sub(r"\s+", " ", text).split(".")[0]
            dt = datetime.strptime(f"{default_year} {base}", "%Y %b %d %H:%M:%S")
            if "." in text:
                dt = dt.replace(microsecond=int(text.split(".")[1][:6].ljust(6, "0")))
        elif kind == "dmy":
            dt = datetime.strptime(text.split(".")[0], "%d %b %Y %H:%M:%S")
            if "." in text:
                dt = dt.replace(microsecond=int(text.split(".")[1][:6].ljust(6, "0")))
        elif kind == "tomcat":
            dt = datetime.strptime(text.split(".")[0], "%d-%b-%Y %H:%M:%S")
        elif kind == "us":
            date, _, rest = text.replace("T", " ", 1).partition(" ")
            first, second, year = date.split("/")
            month, day = (second, first) if day_first else (first, second)
            value = f"{year}-{int(month):02d}-{int(day):02d} " + rest.replace(",", ".").replace(" Z", "Z")
            value = re.sub(r"\s([+-]\d{2}:?\d{2})$", r"\1", value)
            dt = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", value))
        elif kind == "time":
            hms, frac = re.split(r"[.,]", text)
            dt = datetime.strptime(f"1970-01-01 {hms}", "%Y-%m-%d %H:%M:%S")
            dt = dt.replace(microsecond=int(frac[:6].ljust(6, "0")))
        else:
            return None
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Naive times are read as UTC so every file shares one clock.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _epoch_from_json(value) -> float | None:
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 1e17:
            return number / 1e9
        if number > 1e14:
            return number / 1e6
        if number > 1e11:
            return number / 1e3
        return number
    if isinstance(value, str):
        for pattern, kind in _TS_PATTERNS[:2]:
            match = pattern.search(value)
            if match:
                return parse_timestamp(match.group(1), kind, datetime.now().year)
        try:
            return _epoch_from_json(float(value))
        except ValueError:
            return None
    return None


def extract_ids(text: str) -> list[str]:
    found: list[str] = []
    for pattern in ID_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1).rstrip(".,;:)")
            if value not in found:
                found.append(value)
    return found


def _first_key(obj: dict, keys) -> tuple[str | None, object]:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return key, obj[key]
        if "." in key:
            head, _, tail = key.partition(".")
            inner = obj.get(head)
            if isinstance(inner, dict) and inner.get(tail) not in (None, ""):
                return key, inner[tail]
    return None, None


def _parse_json_line(line: str, file: str, line_no: int) -> LogRecord | None:
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    record = LogRecord(file=file, line_no=line_no, raw=line)
    _, ts = _first_key(obj, _JSON_TS_KEYS)
    record.ts = _epoch_from_json(ts) if ts is not None else None
    _, level = _first_key(obj, _JSON_LEVEL_KEYS)
    if isinstance(level, (int, float)):
        # Bunyan/pino numeric levels.
        level = {10: "TRACE", 20: "DEBUG", 30: "INFO", 40: "WARN", 50: "ERROR", 60: "FATAL"}.get(int(level))
    record.level = (normalise_level(str(level)) or "") if level else ""
    _, message = _first_key(obj, _JSON_MSG_KEYS)
    record.message = str(message) if message is not None else line
    _, logger = _first_key(obj, _JSON_LOGGER_KEYS)
    record.logger = str(logger) if logger else ""
    _, err = _first_key(obj, _JSON_ERR_KEYS)
    if err:
        err_text = json.dumps(err) if isinstance(err, (dict, list)) else str(err)
        record.detail = [part for part in err_text.splitlines() if part.strip()]
    for key in _JSON_ID_KEYS:
        if obj.get(key):
            record.ids.append(str(obj[key]))
    skip = set(_JSON_TS_KEYS) | set(_JSON_MSG_KEYS)
    record.fields = {k: v for k, v in obj.items() if k not in skip and not isinstance(v, (dict, list))}
    return record


def _find_timestamp(line: str, default_year: int, day_first: bool = False) -> tuple[float | None, int, int, str | None]:
    """Return (epoch, start, end, kind) for a timestamp in the first part of the line."""
    head = line[:80]
    for pattern, kind in _TS_PATTERNS:
        match = pattern.search(head)
        if match and match.start() <= 40:
            epoch = parse_timestamp(match.group(1), kind, default_year, day_first)
            if epoch is not None:
                return epoch, match.start(), match.end(), kind
    return None, -1, -1, None


def _parse_text_line(line: str, file: str, line_no: int, default_year: int,
                     day_first: bool = False) -> tuple[LogRecord, bool]:
    """Parse one plain-text line. Returns (record, starts_new_event)."""
    record = LogRecord(file=file, line_no=line_no, raw=line)

    access = _ACCESS_RE.match(line)
    if access:
        record.ts = parse_timestamp(access.group("ts"), "clf", default_year)
        status = int(access.group("status"))
        record.level = "ERROR" if status >= 500 else "WARN" if status >= 400 else "INFO"
        record.logger = "access"
        record.message = f'{access.group("method")} {access.group("path")} {status}'
        # Pattern key kept apart from masking so status codes and routes survive grouping.
        route = "/".join("{id}" if re.search(r"\d", seg) else seg
                         for seg in access.group("path").split("?")[0].split("/"))
        record.fields = {
            "client": access.group("client"), "status": status, "method": access.group("method"),
            "path": access.group("path"), "bytes": access.group("size"),
            "pattern": f'{access.group("method")} {route} -> {status}',
        }
        rt = _RESPONSE_TIME_RE.search(access.group("tail") or "")
        if rt:
            try:
                record.fields["response_time"] = float(rt.group(1) or rt.group(2))
            except ValueError:
                pass
        record.ids = extract_ids(line)
        return record, True

    py = _PY_LOGGING_RE.match(line)
    if py and normalise_level(py.group("level")):
        record.level = normalise_level(py.group("level")) or "INFO"
        record.logger = py.group("logger")
        record.message = py.group("msg").strip()
        record.ids = extract_ids(line)
        return record, True

    ts, start, end, kind = _find_timestamp(line, default_year, day_first)
    if ts is None:
        return record, False

    record.ts = ts
    redis = _REDIS_HEAD_RE.match(line[:start]) if kind == "dmy" else None
    if redis:
        mark = _REDIS_MARK_RE.match(line[end:])
        symbol = mark.group("mark") if mark else ""
        record.logger = "redis"
        record.fields.update(pid=redis.group("pid"), role=redis.group("role"))
        record.message = line[end + (mark.end() if mark else 0):].strip()
        # Warnings ("#") and lines without a mark are left to the text, so "Write error saving DB"
        # still counts as an error.
        record.level = {".": "DEBUG", "-": "DEBUG", "*": "INFO"}.get(symbol, "")
        if symbol == "#" and not _ERROR_HINT_RE.search(record.message):
            record.level = "WARN"
        record.ids = extract_ids(line)
        return record, True
    rest = (line[:start] + " " + line[end:]).strip() if start > 0 else line[end:].strip()
    rest = rest.lstrip("]|-: ")

    if kind == "syslog":
        head = _SYSLOG_HEAD_RE.match(rest)
        if head:
            record.logger = head.group("proc")
            record.fields["host"] = head.group("host")
            rest = rest[head.end():]

    # Level: the first level word within the first part of what remains.
    level_match = _LEVEL_RE.search(rest[:60])
    # A level column is in capitals, in brackets or first ("error: ..."). A lower-case word later on
    # ("usage 91% (warning above 85%)") is part of the message, and the level is guessed from the text.
    if level_match and not (level_match.start() == 0 or level_match.group(1).isupper()
                            or level_match.group(0)[0] in "[<"):
        level_match = None
    short = _SHORT_LEVEL_RE.match(rest)
    if level_match:
        record.level = normalise_level(level_match.group(1)) or "INFO"
        rest = (rest[:level_match.start()] + rest[level_match.end():]).strip()
    elif short:
        record.level = _SHORT_LEVELS[short.group(1) or short.group(2)]
        rest = rest[short.end():].strip()
    else:
        record.level = ""

    pid = _SPRING_PID_RE.match(rest)
    if pid:
        rest = rest[pid.end():]
    thread = _THREAD_RE.match(rest)
    if thread:
        record.fields["thread"] = thread.group("thread")
        rest = rest[thread.end():]
    rest = rest.lstrip("-|: ")
    if not record.logger:
        logger = _LOGGER_RE.match(rest)
        name = (logger.group("logger") or logger.group("simple")) if logger else None
        if name and len(name) <= 200:
            record.logger = name
            rest = rest[logger.end():]
            if logger.group("sep") == "|":
                rest = _split_pipe_layout(rest, record)
    # Some layouts write line breaks as "[CRLF]": the first line is the message, the rest is detail.
    if "[CRLF]" in rest:
        rest, *more = rest.split("[CRLF]")
        record.detail = [part for part in more if part.strip()] + record.detail
    record.message = rest.strip() or line.strip()
    record.ids = extract_ids(line)
    return record, True


def _split_pipe_layout(rest: str, record: LogRecord) -> str:
    """Serilog-style "Logger | message | exception | {properties}": return the message.

    The exception goes to the detail lines and the properties to the fields.
    """
    head, sep, props = rest.rpartition(" | {")
    if sep and props.rstrip().endswith("}"):
        try:
            values = json.loads("{" + props)
        except ValueError:
            values = None
        if isinstance(values, dict):
            record.fields.update({k: v for k, v in values.items() if not isinstance(v, (dict, list))})
            rest = head
    message, sep, exception = rest.rpartition(" | ")
    if sep:
        rest = message
        if exception.strip():
            record.detail = [part for part in exception.split("[CRLF]") if part.strip()]
    return rest.rstrip(" |")


def _infer_level(record: LogRecord) -> None:
    if record.level:
        return
    record.level_inferred = True
    text = record.message + (" " + record.detail[0] if record.detail else "")
    if record.detail and any(_PY_EXC_LINE_RE.match(d.strip()) or d.strip().startswith("at ") for d in record.detail):
        record.level = "ERROR"
    elif _ERROR_HINT_RE.search(text):
        record.level = "ERROR"
    elif _WARN_HINT_RE.search(text):
        record.level = "WARN"
    else:
        record.level = "INFO"


def read_lines(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\r\n") for line in handle]


_SLASH_DATE_RE = re.compile(r"(?<![\d/])(\d{1,2})/(\d{1,2})/(\d{4})[ T]\d{2}:\d{2}")
_NAME_DATE_RE = re.compile(r"(?<!\d)(20\d{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])(?!\d)")


def _day_first(lines: list[str], name: str, hint: float | None) -> bool:
    """Whether "03/05/2024" dates in this file mean 3 May (day first) or March 5.

    A day above 12 settles it. Otherwise the date in the file name ("Web.App.20240503.txt"),
    then the file's modified time, picks the reading that lands closer.
    """
    first_seen = None
    for line in lines[:5000]:
        match = _SLASH_DATE_RE.search(line[:60])
        if not match:
            continue
        a, b = int(match.group(1)), int(match.group(2))
        if a > 12 >= b:
            return True
        if b > 12 >= a:
            return False
        first_seen = first_seen or (a, b, int(match.group(3)))
    if first_seen is None:
        return False
    named = _NAME_DATE_RE.search(Path(name).name)
    if named:
        target = datetime(int(named.group(1)), int(named.group(2)), int(named.group(3)), tzinfo=timezone.utc).timestamp()
    elif hint is not None:
        target = hint
    else:
        return False
    a, b, year = first_seen

    def distance(month: int, day: int) -> float:
        try:
            return abs(datetime(year, month, day, tzinfo=timezone.utc).timestamp() - target)
        except ValueError:
            return float("inf")
    return distance(b, a) < distance(a, b)


def parse_lines(lines: list[str], name: str, default_year: int | None = None,
                modified: float | None = None) -> ParsedFile:
    year = default_year or datetime.now().year
    day_first = _day_first(lines, name, modified)
    # In a file where events carry no timestamp, only obvious continuation lines
    # (indented, "at ...", "Caused by:") are folded into the previous event.
    sample = [line for line in lines[:300] if line.strip()]
    structured = sum(
        1 for line in sample
        if line.lstrip().startswith("{") or _find_timestamp(line, year, day_first)[0] is not None
        or _PY_LOGGING_RE.match(line)
    )
    has_event_starts = bool(sample) and structured / len(sample) >= 0.2

    records: list[LogRecord] = []
    json_lines = 0
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        stripped = line.lstrip()
        # Indented JSON under a text event (.NET "Additional Properties") belongs to that event.
        indented_detail = bool(records) and has_event_starts and line[:1].isspace()
        if stripped.startswith("{") and stripped.rstrip().endswith("}") and not indented_detail:
            record = _parse_json_line(stripped, name, line_no)
            if record is not None:
                json_lines += 1
                records.append(record)
                continue
        record, starts_event = _parse_text_line(line, name, line_no, year, day_first)
        if records and not starts_event:
            in_trace = bool(records[-1].detail) and bool(_PY_EXC_LINE_RE.match(line))
            if has_event_starts or in_trace or _CONTINUATION_RE.match(line):
                records[-1].detail.append(line)
                for found in extract_ids(line):
                    if found not in records[-1].ids:
                        records[-1].ids.append(found)
                continue
        if not starts_event:
            record.message = line.strip()
            record.level = ""  # no level on the line: guess it from the text below
            record.ids = extract_ids(line)
        records.append(record)

    for record in records:
        _infer_level(record)

    timestamped = sum(1 for r in records if r.ts is not None)
    if json_lines > len(records) * 0.6:
        fmt = "json"
    elif sum(1 for r in records if r.logger == "access") > len(records) * 0.6:
        fmt = "access"
    elif any(r.fields.get("host") for r in records[:50]):
        fmt = "syslog"
    else:
        fmt = "text"
    return ParsedFile(
        path=name, name=Path(name).name, records=records, line_count=len(lines), format=fmt,
        timestamped=(timestamped / len(records)) if records else 0.0,
    )


def parse_file(path: str | Path, display_name: str | None = None) -> ParsedFile:
    path = Path(path)
    try:
        modified = path.stat().st_mtime
        year = datetime.fromtimestamp(modified).year
    except OSError:
        modified, year = None, None
    parsed = parse_lines(read_lines(path), display_name or str(path), default_year=year, modified=modified)
    parsed.path = str(path)
    return parsed
