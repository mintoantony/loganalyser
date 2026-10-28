"""Analyses run in the background so the window stays responsive; the screen polls their progress."""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path

from ..ai import Settings, run_ai
from ..analysis import Options, analyse
from ..cli import _display_names, collect
from ..parser import parse_file
from . import runs

STAGES = [
    ("read", "Reading files"),
    ("patterns", "Finding patterns"),
    ("rank", "Ranking likely causes"),
    ("link", "Linking requests across files"),
    ("ai", "Asking the AI"),
    ("report", "Building the report"),
]


class Cancelled(Exception):
    pass


class Job:
    def __init__(self, kind: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.stage = "read"
        self.done_stages: list[str] = []
        self.skipped: list[str] = []
        self.message = "Starting"
        self.files_total = 0
        self.files_done = 0
        self.events = 0
        self.current = ""
        self.error: str | None = None
        self.warning: str | None = None
        self.run_id: str | None = None
        self.finished = False
        self.cancel_requested = False
        self.started = time.time()
        self.lock = threading.Lock()

    def enter(self, stage: str, message: str | None = None) -> None:
        if self.cancel_requested:
            raise Cancelled()
        with self.lock:
            if self.stage != stage and self.stage not in self.done_stages:
                self.done_stages.append(self.stage)
            self.stage = stage
            self.message = message or dict(STAGES)[stage]

    def state(self) -> dict:
        with self.lock:
            return {
                "id": self.id, "kind": self.kind, "stage": self.stage, "done": list(self.done_stages),
                "skipped": list(self.skipped), "message": self.message, "filesTotal": self.files_total,
                "filesDone": self.files_done, "events": self.events, "current": self.current,
                "error": self.error, "warning": self.warning, "runId": self.run_id, "finished": self.finished,
                "elapsed": round(time.time() - self.started, 1),
                "stages": [{"id": s, "label": label} for s, label in STAGES],
            }


_jobs: dict[str, Job] = {}


def get(job_id: str) -> Job:
    return _jobs[job_id]


def start_analysis(sources: list[str], baseline: list[str], match: list[str], use_ai: bool,
                   provider: str | None) -> Job:
    job = Job("analysis")
    _jobs[job.id] = job
    threading.Thread(target=_analysis, args=(job, sources, baseline, match, use_ai, provider), daemon=True).start()
    return job


def start_ai(run_id: str, provider: str | None) -> Job:
    job = Job("ai")
    _jobs[job.id] = job
    threading.Thread(target=_ai_only, args=(job, run_id, provider), daemon=True).start()
    return job


def _parse(job: Job, paths: list[Path]) -> list:
    parsed = []
    for path, name in zip(paths, _display_names(paths)):
        job.enter("read", f"Reading {name}")
        with job.lock:
            job.current = name
        result = parse_file(path)
        result.name = name
        for record in result.records:
            record.file = name
        parsed.append(result)
        with job.lock:
            job.files_done += 1
            job.events += len(result.records)
    return parsed


def _analysis(job: Job, sources, baseline, match, use_ai, provider) -> None:
    try:
        try:
            paths = collect(sources)
            base_paths = collect(baseline) if baseline else []
        except SystemExit as exc:  # collect() reports problems this way for the command line
            raise ValueError(str(exc)) from None
        with job.lock:
            job.files_total = len(paths) + len(base_paths)
        files = _parse(job, paths)
        base = _parse(job, base_paths) if base_paths else []
        result = analyse(files, base, Options(match_patterns=match, progress=job.enter))
        _maybe_ai(job, result, use_ai, provider)
        job.enter("report")
        info = runs.save(result, [str(p) for p in paths], [str(p) for p in base_paths])
        with job.lock:
            job.run_id = info["id"]
            job.done_stages.append("report")
            job.message = "Done"
    except Cancelled:
        job.error = "Cancelled."
    except Exception as exc:  # noqa: BLE001 - shown to the person, who can fix the input
        job.error = str(exc) or exc.__class__.__name__
    finally:
        job.finished = True


def _maybe_ai(job: Job, result: dict, use_ai: bool, provider: str | None) -> None:
    if not use_ai:
        job.skipped.append("ai")
        return
    settings = Settings.load()
    cfg = settings.provider(provider)
    problems = cfg.problems()
    if problems:
        job.skipped.append("ai")
        job.warning = f"AI step skipped: {' '.join(problems)}"
        return
    job.enter("ai", f"Asking {cfg.label}")
    report = run_ai(result, cfg, max_lines=settings.privacy.max_lines,
                    hide_personal_data=settings.privacy.redact,
                    progress=lambda message: setattr(job, "message", message))
    if report["status"] != "ok":
        job.warning = f"AI step failed: {report['error']}"


def _ai_only(job: Job, run_id: str, provider: str | None) -> None:
    try:
        for stage in ("read", "patterns", "rank", "link"):
            job.done_stages.append(stage)
        result = runs.load_result(run_id)
        info = runs.load_info(run_id)
        _maybe_ai(job, result, True, provider)
        job.enter("report")
        runs.save(result, info.get("sources", []), info.get("baseline", []), run_id=run_id)
        with job.lock:
            job.run_id = run_id
            job.done_stages.append("report")
            job.message = "Done"
    except KeyError:
        job.error = "That analysis no longer exists."
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc) or exc.__class__.__name__
    finally:
        job.finished = True
