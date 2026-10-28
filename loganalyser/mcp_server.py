"""MCP server: lets Claude, GitHub Copilot and other MCP clients analyse logs with LogAnalyser.

Run with ``python -m loganalyser mcp`` (stdio). Analyses are saved to the same history as the
desktop app, so a run started from a chat can be opened in the app and the other way round.
Log text in the answers follows the app's privacy setting: emails, IPs, tokens and user names
are hidden unless it is switched off.
"""

from __future__ import annotations

import re
import subprocess
import sys
import webbrowser
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import anyio
import anyio.from_thread
import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .ai import Settings
from .ai.advisor import build_evidence
from .ai.redact import redact
from .analysis import Options, analyse
from .cli import _display_names, _parse_time, collect
from .desktop import runs
from .parser import LEVEL_RANK, LEVELS, parse_file
from .rules import load_rules

INSTRUCTIONS = """LogAnalyser reads application logs, finds the most likely cause of a failure and links events across files.
Start with analyse_logs on the folder or files the person gives you; it returns a run id and the ranked causes.
Then use explain_cause, get_evidence, search_logs, get_log_lines and follow_request with that run id to dig in.
Lines are cited as L<number>; pass the number to get_log_lines to see what surrounds it.
The ranking is rule-based and explains itself; check it against the log lines before you state a cause as fact.
Where stack traces name the application's own code, the results list the file, line and method; read the code there when you can.
For several days of mixed logs rather than one incident, that list of code locations is a better guide than the ranking."""

server = MCPServer("LogAnalyser", version=__version__, instructions=INSTRUCTIONS)

_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
_EVIDENCE_CHARS = 40_000  # well inside what AI tools accept from one tool call


# ------------------------------------------------------------------ helpers
def _clean(text: str | None) -> str:
    if not text:
        return ""
    return redact(text) if Settings.load().privacy.redact else text


def _time(ts: float | None, ms: bool = False) -> str:
    if ts is None:
        return "no time"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + (f".{dt.microsecond // 1000:03d}" if ms else "")


@lru_cache(maxsize=4)
def _result(run_id: str) -> dict:
    try:
        return runs.load_result(run_id)
    except (KeyError, OSError):
        raise ToolError(f"No analysis with id {run_id!r}. Use list_analyses to see the saved ones.") from None


def _line(row: list, files: list[dict], detail_lines: int = 12) -> str:
    """One record as text: reference | time | file:line | level | message, with its stack trace indented."""
    idx, file_i, ts, level, _tpl, line_no, message, detail = row[:8]
    message = message if len(message) <= 1500 else message[:1500] + " …"
    out = [f"L{idx} | {_time(ts, ms=True)} | {files[file_i]['name']}:{line_no} | {LEVELS[level]} | {_clean(message)}"]
    if detail and detail_lines:
        lines = detail.splitlines()
        out += ["      " + _clean(text[:300]) for text in lines[:detail_lines]]
        if len(lines) > detail_lines:
            out.append(f"      … {len(lines) - detail_lines} more lines")
    return "\n".join(out)


def _rows(result: dict) -> dict[int, list]:
    return {row[0]: row for row in result["records"]}


def _truncation_note(result: dict) -> str:
    meta = result["meta"]
    if not meta.get("truncated"):
        return ""
    return (f"\nNote: only {meta['embedded']:,} of {meta['records']:,} events were kept for browsing (every warning "
            "and error with the lines around it, plus a sample of the rest). The ranking used every event.")


def _summary(run_id: str, result: dict, report: Path) -> str:
    meta, files = result["meta"], result["meta"]["files"]
    out = [f"Run {run_id}: {meta['records']:,} events in {len(files)} file(s), {meta['templates']:,} patterns, "
           f"from {_time(meta.get('first'))} to {_time(meta.get('last'))} UTC."]
    if meta.get("copiesCounted"):
        out.append(f"{meta['copiesCounted']:,} lines were copies of an event already logged in another file "
                   "(same time, level and message) and are counted once.")
    incident = result.get("incident")
    if incident:
        line = f"Error spike from {_time(incident['start'])} to {_time(incident['end'])}"
        if incident.get("firstFailure"):
            line += f"; first new failure at {_time(incident['firstFailure'])}"
        if incident.get("originFile") is not None:
            line += f" in {files[incident['originFile']]['name']}"
        out.append(line + ".")

    causes = result["causes"]
    if not causes:
        out.append("\nNo warnings or errors were found.")
    else:
        top = causes[0]
        rows = _rows(result)
        out.append(f"\nMost likely cause: {_clean(top['title'])} [{top['category']}], "
                   f"{top['likelihood']:.0f}% relative likelihood, {top['count']:,} events.")
        out.append(_clean(top["summary"]))
        out.append("Why:")
        out += [f"  {'+' if f['weight'] >= 0 else '-'} {f['label']}: {_clean(f['detail'])}" for f in top["factors"][:6]]
        if top.get("firstRecord") in rows:
            out.append("First evidence:\n  " + _line(rows[top["firstRecord"]], files, 6).replace("\n", "\n  "))
        if top.get("chain"):
            followed: dict[str, str] = {}  # several patterns often share one label; keep its first time
            for step in top["chain"]:
                followed.setdefault(_clean(step["title"] or _pattern_text(result, step["template"])), step["deltaText"])
            out.append("What followed: " + "; ".join(f"{delta} {label}" for label, delta in list(followed.items())[:5]))
        if top.get("fixes"):
            out.append("Try: " + " ".join(top["fixes"][:3]))
        if len(causes) > 1:
            out.append("\nOther candidates:")
            out += [f"  {c['rank']}. {_clean(c['title'])} [{c['category']}] {c['likelihood']:.0f}%, {c['count']:,} events"
                    for c in causes[1:6]]

    where = meta.get("codeLocations") or []
    if where:
        out.append("\nErrors by where they were thrown in the application's own code:")
        out += [_where(w) for w in where[:8]]
    if incident and incident.get("precursors"):
        out.append("\nSeen for the first time just before the first failure:")
        out += [f"  {p['beforeText']}: {_clean(_pattern_text(result, p['template']))} (L{p['record']})"
                for p in incident["precursors"][:5]]
    compare = result.get("compare")
    if compare:
        out.append(f"\nCompared with the healthy run: {len(compare['new'])} new patterns, "
                   f"{len(compare['changed'])} changed in frequency, {len(compare['gone'])} missing.")
    for match in result.get("matches") or []:
        out.append(f"Pattern {match['pattern']!r}: {match['count']:,} matching lines.")
    stats = meta.get("traceStats") or {}
    if stats.get("total"):
        out.append(f"{stats['total']:,} requests linked by shared IDs, {stats['multiFile']:,} across files, "
                   f"{stats['withErrors']:,} with errors.")
    out.append(f"\nReport: {report}")
    out.append(f"Next: explain_cause(run_id='{run_id}', rank=N), get_evidence, search_logs, get_log_lines, "
               "follow_request, open_report.")
    return "\n".join(out) + _truncation_note(result)


def _pattern_text(result: dict, template_id: int) -> str:
    return next((t["text"] for t in result["templates"] if t["id"] == template_id), f"pattern {template_id}")


def _analyse(paths: list[str], baseline: list[str], match: list[str], rules_files: list[str],
             since: str | None, until: str | None, progress) -> tuple[str, dict, Path]:
    try:
        files_in = collect(paths)
        base_in = collect(baseline) if baseline else []
    except SystemExit as exc:  # collect() reports problems this way for the command line
        raise ToolError(str(exc)) from None
    for pattern in match:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"The pattern {pattern!r} is not a valid regular expression: {exc}") from None

    total = len(files_in) + len(base_in)
    done = 0

    def parse(group: list[Path]) -> list:
        nonlocal done
        parsed = []
        for path, name in zip(group, _display_names(group)):
            progress(done, total + 3, f"Reading {name}")
            item = parse_file(path)
            item.name = name
            for record in item.records:
                record.file = name
            parsed.append(item)
            done += 1
        return parsed

    files = parse(files_in)
    base = parse(base_in) if base_in else []
    rules = [rule for path in rules_files for rule in load_rules(path)]
    stages = {"patterns": "Finding patterns", "rank": "Ranking likely causes", "link": "Linking requests"}
    step = iter(range(1, 4))
    options = Options(rules=rules, match_patterns=match, incident_start=_parse_time(since),
                      incident_end=_parse_time(until),
                      progress=lambda stage: progress(total + next(step, 3) - 1, total + 3, stages.get(stage, stage)))
    result = analyse(files, base, options)
    info = runs.save(result, [str(p) for p in files_in], [str(p) for p in base_in])
    _result.cache_clear()
    return info["id"], result, runs.report_path(info["id"])


# -------------------------------------------------------------------- tools
@server.tool(title="Analyse logs", annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False,
                                                                open_world_hint=False))
async def analyse_logs(paths: list[str], ctx: Context, baseline: list[str] | None = None,
                       match: list[str] | None = None, rules: list[str] | None = None,
                       since: str | None = None, until: str | None = None) -> str:
    """Analyse log files and find the most likely cause of a failure.

    paths: log files, folders (searched recursively) or glob patterns. Use absolute paths.
    baseline: optional logs from a time when things worked, to see what is new or changed.
    match: optional regular expressions to count and list matching lines.
    rules: optional JSON files with the team's own known-failure signatures.
    since / until: optional ISO 8601 times (UTC unless a zone is given) to set the incident window
    instead of detecting it. Usually leave them out: the time someone noticed a problem is later than
    its cause, and a window that starts too late hides what changed just before.

    Returns a run id, the ranked likely causes with their reasons and first evidence, what changed
    just before, and the path of the interactive HTML report. The run is saved, so later calls and
    the desktop app can use it.
    """
    def progress(done: int, total: int, message: str) -> None:
        try:
            anyio.from_thread.run(ctx.report_progress, done, total, message)
        except Exception:  # noqa: BLE001 - progress is optional; never fail the analysis over it
            pass

    try:
        run_id, result, report = await anyio.to_thread.run_sync(
            _analyse, paths, baseline or [], match or [], rules or [], since, until, progress)
    except (OSError, ValueError) as exc:  # unreadable file, bad time or rules file: the caller can fix these
        raise ToolError(str(exc) or exc.__class__.__name__) from exc
    return _summary(run_id, result, report)


@server.tool(title="Explain a likely cause", annotations=_READ)
def explain_cause(run_id: str, rank: int = 1) -> str:
    """Everything behind one ranked cause: why it ranks where it does, its evidence lines with stack
    traces, the patterns it covers, the failures that followed it, and what to try."""
    result = _result(run_id)
    cause = next((c for c in result["causes"] if c["rank"] == rank), None)
    if cause is None:
        raise ToolError(f"Run {run_id} has {len(result['causes'])} ranked causes; ask for rank 1 to {len(result['causes'])}."
                         if result["causes"] else f"Run {run_id} found no warnings or errors, so there are no causes.")
    files, rows = result["meta"]["files"], _rows(result)
    out = [f"#{cause['rank']} {_clean(cause['title'])} [{cause['category']}]",
           f"{cause['likelihood']:.0f}% relative likelihood (score {cause['score']}), {cause['count']:,} events, "
           f"{_time(cause['first'])} to {_time(cause['last'])} UTC, in " + ", ".join(files[i]["name"] for i in cause["files"]),
           "", _clean(cause["summary"]), "", "Signals:"]
    out += [f"  {'+' if f['weight'] >= 0 else '-'} {f['label']}: {_clean(f['detail'])}" for f in cause["factors"]]
    out.append("\nPatterns:")
    out += [f"  P{tid}: {_clean(_pattern_text(result, tid))}" for tid in cause["templates"][:12]]
    out.append("\nEvidence:")
    out += [_line(rows[i], files) for i in cause["evidence"] if i in rows]
    if cause.get("chain"):
        out.append("\nWhat followed (new failures after it started):")
        out += [f"  {s['deltaText']}: {_clean(s['title'] or _pattern_text(result, s['template']))} "
                f"(x{s['count']}, {', '.join(files[i]['name'] for i in s['files'])})" for s in cause["chain"]]
    if cause.get("code"):
        out.append("\nWhere in the code (first frame in the application's own code, from the stack traces):")
        out += [_where(w) for w in cause["code"]]
    if cause.get("fixes"):
        out.append("\nWhat to try:")
        out += [f"  - {fix}" for fix in cause["fixes"]]
    return "\n".join(out)


def _where(w: dict) -> str:
    return (f"  {w['file']} line {w['line']}, in {w['method']}: {w['exception'] or 'error'} x{w['count']} "
            f"(days: {', '.join(w['days'])}; first L{w['record']})")


@server.tool(title="Get the evidence pack", annotations=_READ)
def get_evidence(run_id: str, max_lines: int = 150) -> str:
    """The whole incident in one text, for forming your own view: overview, every candidate cause
    with its signals, what changed just before, all warning and error patterns, the comparison with
    the healthy run, and up to max_lines log lines chosen around the failures (cited as L<number>).
    This is the same pack the app sends to its own AI second opinion. It is kept under about
    40,000 characters; lines left out can be read with search_logs or get_log_lines."""
    text, _ = build_evidence(_result(run_id), max_lines=max(20, min(max_lines, 1000)),
                             hide_personal_data=Settings.load().privacy.redact, max_chars=_EVIDENCE_CHARS)
    return text


@server.tool(title="Search log lines", annotations=_READ)
def search_logs(run_id: str, query: str = "", regex: bool = False, min_level: str | None = None,
                file: str | None = None, pattern_id: int | None = None, limit: int = 40) -> str:
    """Find lines in an analysed run. query matches the message, stack trace and original line
    (plain text, case-insensitive, or a regular expression with regex=true). min_level is one of
    TRACE, DEBUG, INFO, WARN, ERROR, FATAL. file filters by file name (part of it is enough).
    pattern_id is a pattern from explain_cause (P<number>). Returns the first matches in time order."""
    result = _result(run_id)
    files = result["meta"]["files"]
    if query and regex:
        try:
            compiled = re.compile(query, re.IGNORECASE)
        except re.error as exc:
            raise ToolError(f"Not a valid regular expression: {exc}") from None
        hit = lambda text: compiled.search(text) is not None
    else:
        needle = query.lower()
        hit = lambda text: needle in text.lower()
    level = None
    if min_level:
        level = LEVEL_RANK.get(min_level.upper().replace("WARNING", "WARN"))
        if level is None:
            raise ToolError(f"min_level must be one of {', '.join(LEVELS)}.")
    file_ids = None
    if file:
        file_ids = {f["index"] for f in files if file.lower() in f["name"].lower()}
        if not file_ids:
            raise ToolError(f"No file name contains {file!r}. Files: {', '.join(f['name'] for f in files)}")

    limit = max(1, min(limit, 200))
    found, shown = 0, []
    for row in result["records"]:
        if level is not None and row[3] < level:
            continue
        if file_ids is not None and row[1] not in file_ids:
            continue
        if pattern_id is not None and row[4] != pattern_id:
            continue
        if query and not hit("\n".join(part for part in (row[6], row[7], row[11] if len(row) > 11 else None) if part)):
            continue
        found += 1
        if len(shown) < limit:
            shown.append(_line(row, files, detail_lines=4))
    if not found:
        return "No matching lines." + _truncation_note(result)
    head = f"{found:,} matching lines" + (f", showing the first {len(shown)}" if found > len(shown) else "") + ":"
    return "\n".join([head, *shown]) + _truncation_note(result)


@server.tool(title="Show lines around a line", annotations=_READ)
def get_log_lines(run_id: str, line: int, before: int = 10, after: int = 10) -> str:
    """The lines around one event (L<number> from any other answer), from the same file in file order,
    with full stack traces for the event itself."""
    result = _result(run_id)
    files, rows = result["meta"]["files"], _rows(result)
    if line not in rows:
        raise ToolError(f"L{line} is not in this run's saved lines. Use search_logs to find lines.")
    target = rows[line]
    same_file = sorted((r for r in result["records"] if r[1] == target[1]), key=lambda r: r[5])
    pos = next(i for i, r in enumerate(same_file) if r[0] == line)
    window = same_file[max(0, pos - max(0, min(before, 100))): pos + max(0, min(after, 100)) + 1]
    out = [f"{files[target[1]]['name']}, around line {target[5]}:"]
    for row in window:
        text = _line(row, files, detail_lines=60 if row[0] == line else 2)
        out.append(("> " if row[0] == line else "  ") + text.replace("\n", "\n  "))
    return "\n".join(out)


@server.tool(title="Follow a request across files", annotations=_READ)
def follow_request(run_id: str, request_id: str) -> str:
    """Every event that carries a request, trace, correlation or order ID, across all files, in time
    order. Without a known ID, call it with request_id="" to list the failing requests that were linked."""
    result = _result(run_id)
    files, rows = result["meta"]["files"], _rows(result)
    if not request_id:
        failing = [t for t in result.get("traces", []) if t["errors"]][:20]
        if not failing:
            return "No failing requests were linked across lines in this run."
        return "Failing requests (ID, events, errors, files):\n" + "\n".join(
            f"  {_clean(t['id'])}: {t['count']} events, {t['errors']} errors, "
            + ", ".join(files[i]["name"] for i in t["files"]) for t in failing)
    trace = next((t for t in result.get("traces", []) if t["id"] == request_id), None)
    if trace:
        idxs = [i for i in trace["records"] if i in rows]
    else:
        idxs = [r[0] for r in result["records"] if r[9] and request_id in r[9]]
    if not idxs:
        needle = request_id.lower()
        idxs = [r[0] for r in result["records"] if needle in r[6].lower()][:400]
    if not idxs:
        return f"No events mention {request_id!r}."
    idxs.sort(key=lambda i: (rows[i][2] or 0, i))
    names = sorted({files[rows[i][1]]["name"] for i in idxs})
    span = [rows[i][2] for i in idxs if rows[i][2] is not None]
    out = [f"{len(idxs)} events in {len(names)} file(s) ({', '.join(names)})"
           + (f" over {max(span) - min(span):.3f}s" if span else "") + ":"]
    out += [_line(rows[i], files, detail_lines=6) for i in idxs[:200]]
    return "\n".join(out)


@server.tool(title="List past analyses", annotations=_READ)
def list_analyses(limit: int = 10) -> str:
    """Saved analyses, newest first, including ones made in the desktop app."""
    items = runs.history()[: max(1, min(limit, 100))]
    if not items:
        return "No saved analyses yet. Use analyse_logs."
    out = []
    for item in items:
        likely = f" ({item['likelihood']:.0f}%)" if item.get("likelihood") is not None else ""
        out.append(f"{item['id']}  {item['created']}  {_clean(item['title'])}{likely}  "
                   f"{item['records']:,} events in {', '.join(item['files'][:4])}"
                   + (" …" if len(item["files"]) > 4 else ""))
    return "\n".join(out)


@server.tool(title="Open the report", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False,
                                                                  idempotent_hint=False))
def open_report(run_id: str, in_app: bool = False) -> str:
    """Open the interactive report for a run on this computer: in the default browser, or with
    in_app=true in the LogAnalyser desktop app."""
    try:
        path = runs.report_path(run_id)
    except KeyError:
        raise ToolError(f"No analysis with id {run_id!r}.") from None
    if in_app:
        _launch_app(run_id)
        return f"Opening run {run_id} in the LogAnalyser app."
    webbrowser.open(path.resolve().as_uri())
    return f"Opened {path} in the browser."


def _launch_app(run_id: str) -> None:
    """Start the desktop app on a run, fully detached so it does not share this server's stdio."""
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--run", run_id]
    else:
        command = [sys.executable, "-m", "loganalyser.desktop", "--run", run_id]
    kwargs: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                    "close_fds": True}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(command, **kwargs)  # noqa: S603 - our own executable, fixed arguments


# ------------------------------------------------------------------ prompts
@server.prompt(title="Investigate an incident")
def investigate(logs: str) -> str:
    """Find out why something broke, from its logs."""
    return (f"Find out why it broke, using the logs at {logs}.\n"
            "1. Run analyse_logs on them.\n"
            "2. Read the top cause with explain_cause, and check its evidence with get_log_lines.\n"
            "3. If the ranking looks doubtful, read get_evidence and say what you think instead, and why.\n"
            "4. Answer with: the most likely root cause, the lines that prove it (L numbers), what followed, "
            "and what to do now and later.")


def main() -> int:
    server.run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
