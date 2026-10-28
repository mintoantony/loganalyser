import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_copilot_and_codex_agents_match_the_claude_agent():
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "sync_agents.py"), "--check"],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
