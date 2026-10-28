"""Command line: ``python -m loganalyser analyse <logs...>`` and ``python -m loganalyser demo``."""

from __future__ import annotations

import argparse
import glob
import json
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, report
from .analysis import Options, analyse
from .parser import ParsedFile, parse_file
from .rules import load_rules

_LOG_SUFFIXES = {".log", ".txt", ".out", ".err", ".json", ".jsonl", ".ndjson", ".gz", ".csv", ".trace"}


def collect(inputs: list[str]) -> list[Path]:
    """Expand files, folders and glob patterns into a sorted list of log files."""
    found: list[Path] = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            found += sorted(p for p in path.rglob("*") if p.is_file() and (
                p.suffix.lower() in _LOG_SUFFIXES or ".log" in p.name.lower()))
        elif path.is_file():
            found.append(path)
        else:
            matches = sorted(p for p in map(Path, glob.glob(item, recursive=True)) if p.is_file())
            if not matches:
                raise SystemExit(f"Nothing found at {item}. Give a log file, a folder or a pattern such as logs/*.log.")
            found += matches
    unique = list(dict.fromkeys(p.resolve() for p in found))
    if not unique:
        raise SystemExit("No log files found in what you gave.")
    return unique


def _display_names(paths: list[Path]) -> list[str]:
    """Short names that stay unique: the file name, plus parent folders only when needed."""
    names = [p.name for p in paths]
    depth = 1
    while len(set(names)) < len(names) and depth < 6:
        depth += 1
        names = ["/".join(p.parts[-depth:]) for p in paths]
    return names


def _parse_all(paths: list[Path], label: str) -> list[ParsedFile]:
    parsed = []
    for path, name in zip(paths, _display_names(paths)):
        started = time.perf_counter()
        result = parse_file(path)
        result.name = name
        for record in result.records:
            record.file = name
        print(f"  {label} {name}: {len(result.records):,} events from {result.line_count:,} lines "
              f"({result.format}, {time.perf_counter() - started:.1f}s)", file=sys.stderr)
        parsed.append(result)
    return parsed


def _parse_time(value: str | None) -> float | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def cmd_analyse(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    print("Reading logs", file=sys.stderr)
    files = _parse_all(collect(args.logs), "read")
    baseline = _parse_all(collect(args.baseline), "baseline") if args.baseline else []

    rules = []
    for rules_file in args.rules or []:
        rules += load_rules(rules_file)
    options = Options(rules=rules, match_patterns=args.match or [],
                      incident_start=_parse_time(args.since), incident_end=_parse_time(args.until),
                      max_records=args.max_lines)
    print("Analysing", file=sys.stderr)
    result = analyse(files, baseline, options)
    if getattr(args, "ai", False):
        _run_ai(args, result)

    out = Path(args.output)
    report.write(result, out, args.title)
    if args.json:
        Path(args.json).write_text(json.dumps({k: v for k, v in result.items() if k != "records"},
                                              indent=2, default=str), encoding="utf-8")

    _print_summary(result, out, time.perf_counter() - started)
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


def _run_ai(args: argparse.Namespace, result: dict) -> None:
    """Add the configured LLM's reading. Uses the desktop app's saved settings unless overridden."""
    from dataclasses import replace

    from .ai import Settings, run_ai

    settings = Settings.load()
    cfg = settings.provider(args.ai_provider)
    cfg = replace(cfg, model=args.ai_model or cfg.model, base_url=args.ai_url or cfg.base_url)
    problems = cfg.problems()
    if problems:
        print(f"AI step skipped: {' '.join(problems)} (set it in the desktop app, or use --ai-model / the "
              f"{cfg.spec.get('key_env') or 'provider'} environment variable)", file=sys.stderr)
        return
    report = run_ai(result, cfg, max_lines=args.ai_lines or settings.privacy.max_lines,
                    hide_personal_data=not args.no_redact,
                    progress=lambda message: print(message, file=sys.stderr))
    if report["status"] != "ok":
        print(f"AI step failed: {report['error']}", file=sys.stderr)


def _print_summary(result: dict, out: Path, seconds: float) -> None:
    meta = result["meta"]
    print(f"\n{meta['records']:,} events in {len(meta['files'])} file(s), "
          f"{meta['templates']:,} patterns, analysed in {seconds:.1f}s", file=sys.stderr)
    causes = result["causes"]
    if causes:
        print("\nMost likely causes:", file=sys.stderr)
        for cause in causes[:3]:
            print(f"  {cause['rank']}. {cause['title']}  ({cause['likelihood']:.0f}%, {cause['count']:,} events)",
                  file=sys.stderr)
    else:
        print("\nNo warnings or errors found.", file=sys.stderr)
    ai = result.get("ai")
    if ai and ai["status"] == "ok":
        rc = ai["analysis"]["rootCause"]
        stance = "agrees" if rc["agreesWithEngine"] else "disagrees"
        print(f"\n{ai['providerLabel']} ({ai['model']}) {stance}: {rc['title']} "
              f"({rc['confidence']} confidence, {ai['seconds']}s)", file=sys.stderr)
    print(f"\nReport: {out.resolve()}", file=sys.stderr)


def cmd_demo(args: argparse.Namespace) -> int:
    from .samples import generate

    folder = Path(args.folder)
    generate(folder)
    print(f"Wrote demo logs to {folder.resolve()}", file=sys.stderr)
    analyse_args = argparse.Namespace(
        logs=[str(folder / "incident")], baseline=[str(folder / "baseline")], output=args.output,
        rules=None, match=None, since=None, until=None, json=None, title=None,
        max_lines=60_000, open=args.open, ai=False,
    )
    return cmd_analyse(analyse_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loganalyser",
        description="Read logs, find the likely cause of a failure, match events across files and runs, "
                    "and write an interactive HTML report.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", aliases=["analyze"], help="Analyse log files and write a report")
    a.add_argument("logs", nargs="+", help="Log files, folders or patterns such as 'logs/*.log'")
    a.add_argument("-o", "--output", default="log-report.html", help="Where to write the HTML report")
    a.add_argument("-b", "--baseline", nargs="+", metavar="LOGS",
                   help="Logs from a healthy run to compare with (files, folders or patterns)")
    a.add_argument("-m", "--match", action="append", metavar="REGEX",
                   help="Also look for this pattern; can be given more than once")
    a.add_argument("-r", "--rules", action="append", metavar="FILE",
                   help="JSON file with your own known-failure rules")
    a.add_argument("--since", help="Treat the incident as starting at this time (ISO 8601, UTC if no zone)")
    a.add_argument("--until", help="Treat the incident as ending at this time")
    a.add_argument("--json", metavar="FILE", help="Also write the findings as JSON")
    a.add_argument("--title", help="Title for the report")
    a.add_argument("--max-lines", type=int, default=60_000,
                   help="Most events to embed in the report for browsing (analysis always uses all)")
    a.add_argument("--open", action="store_true", help="Open the report in the browser when done")
    ai = a.add_argument_group("AI second opinion (optional; uses the desktop app's saved settings)")
    ai.add_argument("--ai", action="store_true", help="Also ask the configured LLM for its reading of the incident")
    ai.add_argument("--ai-provider", choices=["anthropic", "openai", "gemini", "azure", "openrouter", "ollama", "custom"],
                    help="Provider to use instead of the saved default")
    ai.add_argument("--ai-model", help="Model (or Azure deployment) to use instead of the saved one")
    ai.add_argument("--ai-url", help="Endpoint URL to use instead of the saved one")
    ai.add_argument("--ai-lines", type=int, metavar="N",
                    help="Most log lines to send as evidence (default: the saved setting, 300)")
    ai.add_argument("--no-redact", action="store_true",
                    help="Send log lines as they are, without hiding emails, IPs, tokens and user names")
    a.set_defaults(func=cmd_analyse)

    d = sub.add_parser("demo", help="Write sample logs from a made-up incident and analyse them")
    d.add_argument("--folder", default="demo-logs", help="Where to write the sample logs")
    d.add_argument("-o", "--output", default="demo-report.html", help="Where to write the HTML report")
    d.add_argument("--open", action="store_true", help="Open the report in the browser when done")
    d.set_defaults(func=cmd_demo)

    m = sub.add_parser("mcp", help="Run as an MCP server (stdio) for Claude, Copilot and other AI tools")
    m.set_defaults(func=cmd_mcp)
    return parser


def cmd_mcp(args: argparse.Namespace) -> int:
    try:
        from .mcp_server import main as serve
    except ImportError:
        raise SystemExit('The MCP server needs the mcp package: pip install "loganalyser[mcp]"') from None
    return serve()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
