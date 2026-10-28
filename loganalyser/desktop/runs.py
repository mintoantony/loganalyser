"""Past analyses, kept in the app-data folder so they can be reopened.

Each run is a folder holding the full result (so the AI step can be re-run
later), the rendered report, and a small summary for the history list.
"""

from __future__ import annotations

import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import report
from ..ai import Settings

_ID = re.compile(r"^[0-9a-f]{12}$")


def folder() -> Path:
    path = Settings.folder() / "runs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _dir(run_id: str) -> Path:
    if not _ID.match(run_id or ""):
        raise KeyError(run_id)
    path = folder() / run_id
    if not path.is_dir():
        raise KeyError(run_id)
    return path


def summary(run_id: str, result: dict, sources: list[str], baseline: list[str]) -> dict:
    top = result["causes"][0] if result["causes"] else None
    ai = result.get("ai")
    ai_summary = None
    if ai:
        ai_summary = {"status": ai["status"], "provider": ai["providerLabel"], "model": ai.get("model"),
                      "error": ai.get("error")}
        if ai["status"] == "ok":
            rc = ai["analysis"]["rootCause"]
            ai_summary.update({"title": rc["title"], "agrees": rc["agreesWithEngine"], "confidence": rc["confidence"]})
    meta = result["meta"]
    return {
        "id": run_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "title": top["title"] if top else "No warnings or errors found",
        "category": top["category"] if top else None,
        "likelihood": top["likelihood"] if top else None,
        "files": [f["name"] for f in meta["files"]],
        "records": meta["records"],
        "first": meta.get("first"), "last": meta.get("last"),
        "sources": sources, "baseline": baseline, "ai": ai_summary,
    }


def save(result: dict, sources: list[str], baseline: list[str], run_id: str | None = None) -> dict:
    run_id = run_id or uuid.uuid4().hex[:12]
    path = folder() / run_id
    path.mkdir(parents=True, exist_ok=True)
    (path / "result.json").write_text(json.dumps(result, separators=(",", ":"), default=str), encoding="utf-8")
    report.write(result, path / "report.html")
    info = summary(run_id, result, sources, baseline)
    if (path / "run.json").exists():
        info["created"] = json.loads((path / "run.json").read_text(encoding="utf-8")).get("created", info["created"])
    (path / "run.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def history() -> list[dict]:
    items = []
    for path in folder().iterdir():
        try:
            items.append(json.loads((path / "run.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    items.sort(key=lambda r: r.get("created", ""), reverse=True)
    return items


def load_result(run_id: str) -> dict:
    return json.loads((_dir(run_id) / "result.json").read_text(encoding="utf-8"))


def load_info(run_id: str) -> dict:
    return json.loads((_dir(run_id) / "run.json").read_text(encoding="utf-8"))


def report_path(run_id: str) -> Path:
    return _dir(run_id) / "report.html"


def delete(run_id: str) -> None:
    shutil.rmtree(_dir(run_id))
