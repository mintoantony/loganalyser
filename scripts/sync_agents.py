"""Write the log investigator for GitHub Copilot and Codex from the Claude Code agent.

The instructions live in one place, .claude/agents/log-investigator.md. Run this after changing them:

    python scripts/sync_agents.py          # rewrite the copies
    python scripts/sync_agents.py --check  # exit 1 if a copy is out of date (used by the tests)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / ".claude" / "agents" / "log-investigator.md"
NOTE = "Generated from .claude/agents/log-investigator.md by scripts/sync_agents.py. Edit that file, not this one."


def _source() -> tuple[str, str]:
    text = SOURCE.read_text(encoding="utf-8")
    match = re.match(r"---\n(.*?)\n---\n\n?(.*)", text, re.S)
    description = re.search(r"^description: (.+)$", match.group(1), re.M).group(1).strip()
    return description, match.group(2).rstrip() + "\n"


def _yaml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def outputs() -> dict[Path, str]:
    description, body = _source()
    if "'''" in body:
        raise SystemExit("The instructions contain ''' and cannot be written as a TOML literal string.")
    return {
        # VS Code Copilot Chat, Copilot CLI and the Copilot cloud agent read .github/agents/*.agent.md.
        ROOT / ".github" / "agents" / "log-investigator.agent.md": (
            "---\n"
            "name: log-investigator\n"
            f"description: {_yaml_string(description)}\n"
            "tools: ['read', 'search', 'loganalyser/*']\n"
            "---\n\n"
            f"<!-- {NOTE} -->\n\n{body}"),
        # Codex custom agent (subagent), one TOML file per agent.
        ROOT / ".codex" / "agents" / "log-investigator.toml": (
            f"# {NOTE}\n"
            'name = "log-investigator"\n'
            f"description = {_yaml_string(description)}\n"
            f"developer_instructions = '''\n{body}'''\n"),
        # Codex skill, so it can also run in the main thread: $investigate-logs
        ROOT / ".agents" / "skills" / "investigate-logs" / "SKILL.md": (
            "---\n"
            "name: investigate-logs\n"
            f"description: {_yaml_string(description)}\n"
            "---\n\n"
            f"<!-- {NOTE} -->\n\n{body}"),
    }


def main(argv: list[str]) -> int:
    stale = []
    for path, content in outputs().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if "--check" in argv:
            stale.append(path.relative_to(ROOT).as_posix())
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT).as_posix()}")
    if stale:
        print("Out of date (run python scripts/sync_agents.py): " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
