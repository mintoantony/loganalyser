"""Write the analysis as one self-contained HTML file."""

from __future__ import annotations

import html
import json
from pathlib import Path

_TEMPLATE = Path(__file__).parent / "assets" / "report.html"


def render(result: dict, title: str | None = None) -> str:
    template = _TEMPLATE.read_text(encoding="utf-8")
    if title is None:
        top = result["causes"][0]["title"] if result["causes"] else "No errors found"
        title = f"Log analysis: {top}"
    payload = json.dumps(result, separators=(",", ":"), ensure_ascii=False, default=str)
    # Keep the JSON from closing the <script> element it lives in.
    payload = payload.replace("</", "<\\/").replace("<!--", "\\u003c!--")
    return template.replace("__TITLE__", html.escape(title)).replace("__DATA__", payload)


def write(result: dict, path: str | Path, title: str | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(result, title), encoding="utf-8")
    return path
