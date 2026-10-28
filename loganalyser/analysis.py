"""Find the likely cause of an incident and match log events across files and runs.

The ranking works on patterns, not single lines. For every warning or error
pattern it asks the questions an experienced engineer asks:

* Is it a known way for systems to break, and is that kind of failure
  usually a cause or a symptom?
* Did it start before the error spike, or only once things were already
  failing?
* How many other failures came after it?
* Is it concentrated in the incident, or does it also happen when all is well?
* Did it show up in the service that failed first?
* Is it new compared with a healthy run (when a baseline is given)?

Each answer becomes a factor with a plain-language reason, so the report can
show why a cause ranks where it does.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import median

from .parser import LEVEL_RANK, LEVELS, LogRecord, ParsedFile
from .rules import BUILTIN_RULES, Rule
from .templates import Template, TemplateMiner

MAX_EMBEDDED_RECORDS = 60_000
_NICE_BUCKETS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200,
                 10800, 21600, 43200, 86400, 172800, 604800]
_LEVEL_WEIGHT = {"FATAL": 1.0, "ERROR": 0.8, "WARN": 0.5, "INFO": 0.2, "DEBUG": 0.1, "TRACE": 0.1}
_CAUSED_BY_RE = re.compile(r"Caused by:\s*([\w.$]+(?:Exception|Error)[^\n]*)")


@dataclass(slots=True)
class TemplateStats:
    template: Template
    level: str = "INFO"
    first: float | None = None
    last: float | None = None
    files: Counter = field(default_factory=Counter)
    rule: Rule | None = None
    rules: list[str] = field(default_factory=list)
    baseline_count: int = 0
    root_exception: str = ""


@dataclass(slots=True)
class Options:
    rules: list[Rule] = field(default_factory=list)
    match_patterns: list[str] = field(default_factory=list)
    incident_start: float | None = None
    incident_end: float | None = None
    max_records: int = MAX_EMBEDDED_RECORDS
    progress: object = None  # optional callable(stage: str), told when each stage starts


def _fmt_delta(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.0f}s" if seconds >= 10 else f"{seconds:.1f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    return f"{hours // 24}d {hours % 24}h"


def _fmt_time(epoch: float | None) -> str:
    if epoch is None:
        return "unknown time"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S")


def _pick_bucket(span: float) -> int:
    for size in _NICE_BUCKETS:
        if span / size <= 120:
            return size
    return _NICE_BUCKETS[-1]


def _fill_missing_times(records: list[LogRecord]) -> None:
    """Records without a timestamp inherit the previous record's time in the same file."""
    last: float | None = None
    for record in records:
        if record.ts is None:
            record.ts = last
        else:
            last = record.ts
    # Leading records with no earlier time take the first known one.
    first_known = next((r.ts for r in records if r.ts is not None), None)
    for record in records:
        if record.ts is not None:
            break
        record.ts = first_known


def _rule_for(text: str, rules: list[Rule]) -> tuple[Rule | None, list[str]]:
    matched = [rule for rule in rules if rule.matches(text)]
    if not matched:
        return None, []
    custom = [r for r in matched if r.custom]
    specific = [r for r in matched if r.id != "app_exception"]
    pool = custom or specific or matched
    best = max(pool, key=lambda r: r.rootness)
    return best, [r.id for r in matched]


def _detect_bursts(errors: list[int]) -> list[tuple[int, int]]:
    """Return (start, end) bucket ranges where the error rate jumps well above normal."""
    if not errors or max(errors) == 0:
        return []
    med = median(errors)
    mad = median(abs(e - med) for e in errors) * 1.4826
    threshold = max(3.0, med + 3 * max(mad, 1.0))
    if max(errors) < threshold:
        # No clear spike: treat the busiest stretch as the incident.
        threshold = max(1.0, max(errors) * 0.5)
    ranges: list[tuple[int, int]] = []
    for i, value in enumerate(errors):
        if value >= threshold:
            if ranges and i - ranges[-1][1] <= 2:
                ranges[-1] = (ranges[-1][0], i)
            else:
                ranges.append((i, i))
    return ranges


class Analysis:
    def __init__(self, files: list[ParsedFile], baseline: list[ParsedFile] | None = None,
                 options: Options | None = None):
        self.files = files
        self.baseline = baseline or []
        self.options = options or Options()
        # --match patterns are searches, not claims about causes: they feed _matches() only.
        self.rules: list[Rule] = list(self.options.rules) + list(BUILTIN_RULES)
        self.truncated = False
        self._first_failure: float | None = None
        self._candidate_ids: set[int] = set()
        self._emerging_first: dict[int, float] = {}
        self._origin_file: int | None = None
        self.trace_stats = {"total": 0, "multiFile": 0, "withErrors": 0}

        self.file_index = {f.path: i for i, f in enumerate(files)}
        self.records: list[LogRecord] = []
        self.record_file: list[int] = []
        self.miner = TemplateMiner()
        self.stats: dict[int, TemplateStats] = {}

    # ------------------------------------------------------------------ build
    def run(self) -> dict:
        for index, parsed in enumerate(self.files):
            _fill_missing_times(parsed.records)
            for record in parsed.records:
                self.records.append(record)
                self.record_file.append(index)

        order = sorted(range(len(self.records)),
                       key=lambda i: (self.records[i].ts if self.records[i].ts is not None else 0,
                                      self.record_file[i], self.records[i].line_no))
        self.records = [self.records[i] for i in order]
        self.record_file = [self.record_file[i] for i in order]

        self._step("patterns")
        for i, record in enumerate(self.records):
            template = self._add_template(record, i)
            record.template_id = template.id

        baseline_counts: Counter = Counter()
        baseline_total = 0
        for parsed in self.baseline:
            for record in parsed.records:
                template = self._add_template(record, -1)
                baseline_counts[template.id] += 1
                baseline_total += 1
        self.baseline_total = baseline_total

        self._step("rank")
        self._collect_stats(baseline_counts)
        timeline = self._timeline()
        incident = self._incident_window(timeline)
        causes = self._rank_causes(timeline, incident)
        if incident is not None:
            incident["firstFailure"] = self._first_failure
            incident["originFile"] = self._origin_file
            incident["precursors"] = self._precursors(timeline)
        self._step("link")
        traces = self._traces()
        return {
            "meta": self._meta(),
            "levels": LEVELS,
            "templates": self._templates_json(timeline),
            "timeline": timeline,
            "incident": incident,
            "causes": causes,
            "signatures": self._signatures(),
            "traces": traces,
            "compare": self._compare() if self.baseline else None,
            "matches": self._matches(),
            "records": self._records_json(),
        }

    def _step(self, stage: str) -> None:
        if callable(self.options.progress):
            self.options.progress(stage)

    def _add_template(self, record: LogRecord, index: int) -> Template:
        key = record.fields.get("pattern")
        if key:
            return self.miner.add(key, index, masked=True)
        return self.miner.add(record.message, index)

    def _collect_stats(self, baseline_counts: Counter) -> None:
        for template in self.miner.templates:
            stats = TemplateStats(template=template, baseline_count=baseline_counts.get(template.id, 0))
            live = [i for i in template.record_ids if i >= 0]
            if live:
                worst = max((self.records[i] for i in live), key=lambda r: LEVEL_RANK.get(r.level, 2))
                stats.level = worst.level
                times = [self.records[i].ts for i in live if self.records[i].ts is not None]
                stats.first = min(times) if times else None
                stats.last = max(times) if times else None
                stats.files = Counter(self.record_file[i] for i in live)
                samples = [live[0], live[len(live) // 2], live[-1]]
                text = "\n".join(self._match_text(self.records[i]) for i in dict.fromkeys(samples))
                stats.rule, stats.rules = _rule_for(text, self.rules)
                caused = _CAUSED_BY_RE.findall(text)
                if caused:
                    stats.root_exception = caused[-1].strip()[:200]
            self.stats[template.id] = stats

    @staticmethod
    def _match_text(record: LogRecord) -> str:
        return record.message + ("\n" + "\n".join(record.detail[:40]) if record.detail else "")

    # --------------------------------------------------------------- timeline
    def _timeline(self) -> dict:
        times = [r.ts for r in self.records if r.ts is not None]
        if not times:
            return {"start": None, "end": None, "bucket": 0, "counts": [], "byFile": [], "bursts": []}
        start, end = min(times), max(times)
        size = _pick_bucket(max(end - start, 1))
        start = math.floor(start / size) * size
        n = int((end - start) // size) + 1
        counts = [[0] * len(LEVELS) for _ in range(n)]
        by_file = [[0] * n for _ in self.files]
        for record, file_idx in zip(self.records, self.record_file):
            if record.ts is None:
                continue
            b = int((record.ts - start) // size)
            counts[b][LEVEL_RANK.get(record.level, 2)] += 1
            if LEVEL_RANK.get(record.level, 2) >= LEVEL_RANK["ERROR"]:
                by_file[file_idx][b] += 1
        errors = [c[LEVEL_RANK["ERROR"]] + c[LEVEL_RANK["FATAL"]] for c in counts]
        bursts = [{"start": start + a * size, "end": start + (b + 1) * size,
                   "errors": sum(errors[a:b + 1]), "peak": max(errors[a:b + 1])}
                  for a, b in _detect_bursts(errors)]
        return {"start": start, "end": end, "bucket": size, "counts": counts,
                "byFile": by_file, "bursts": bursts}

    def _incident_window(self, timeline: dict) -> dict | None:
        if self.options.incident_start is not None or self.options.incident_end is not None:
            start = self.options.incident_start if self.options.incident_start is not None else timeline["start"]
            end = self.options.incident_end if self.options.incident_end is not None else timeline["end"]
            return {"start": start, "end": end, "source": "given"}
        bursts = timeline["bursts"]
        if not bursts:
            return None
        main = max(bursts, key=lambda b: b["errors"])
        # The incident runs from the first burst that leads into the main one.
        first = main
        for burst in bursts:
            if burst["start"] <= main["start"] and main["start"] - burst["end"] <= 10 * timeline["bucket"]:
                first = burst
                break
        return {"start": first["start"], "end": main["end"], "source": "detected",
                "errors": sum(b["errors"] for b in bursts if first["start"] <= b["start"] <= main["start"])}

    # ----------------------------------------------------------------- causes
    def _rank_causes(self, timeline: dict, incident: dict | None) -> list[dict]:
        candidates = [s for s in self.stats.values()
                      if any(i >= 0 for i in s.template.record_ids)
                      and (LEVEL_RANK.get(s.level, 2) >= LEVEL_RANK["WARN"] or (s.rule and s.rule.id != "app_exception"))]
        if not candidates:
            return []
        self._candidate_ids = {s.template.id for s in candidates}

        span_start, span_end = timeline["start"], timeline["end"]
        if incident and span_start is not None:
            lead = max(5 * timeline["bucket"], 0.1 * (span_end - span_start))
            win_start, win_end, onset = incident["start"] - lead, incident["end"], incident["start"]
        else:
            win_start, win_end, onset = span_start, span_end, None

        def in_window(ts):
            return ts is not None and win_start is not None and win_start <= ts <= win_end

        # A pattern "emerges" in the incident when it never occurred before the window
        # opened. Patterns that were already there are chronic and cannot have started it.
        emerging: dict[int, int] = {}  # template id -> first record index inside the window
        chronic: set[int] = set()
        for stats in candidates:
            live = [i for i in stats.template.record_ids if i >= 0]
            inside = [i for i in live if in_window(self.records[i].ts)]
            if not inside:
                continue
            if incident and any(self.records[i].ts is not None and self.records[i].ts < win_start for i in live):
                chronic.add(stats.template.id)
            else:
                emerging[stats.template.id] = min(inside, key=lambda i: (self.records[i].ts, i))
        self._emerging_first = {tid: self.records[i].ts for tid, i in emerging.items()}
        if emerging:
            self._first_failure = min(self._emerging_first.values())

        # Which file shows a new failure first.
        file_onset: dict[int, float] = {}
        for tid, i in sorted(emerging.items(), key=lambda kv: self.records[kv[1]].ts):
            file_onset.setdefault(self.record_file[i], self.records[i].ts)
        origin_file = min(file_onset, key=file_onset.get) if len(file_onset) > 1 else None
        self._origin_file = origin_file

        # Patterns sharing a known cause form one hypothesis.
        groups: dict[str, list[TemplateStats]] = defaultdict(list)
        for stats in candidates:
            key = stats.rule.id if stats.rule and stats.rule.id != "app_exception" else f"t{stats.template.id}"
            groups[key].append(stats)

        group_first: dict[str, tuple[float, int]] = {}
        for key, members in groups.items():
            firsts = [(self.records[emerging[m.template.id]].ts, emerging[m.template.id])
                      for m in members if m.template.id in emerging]
            if firsts:
                group_first[key] = min(firsts)
        ordered = sorted(group_first, key=group_first.get)
        position = {key: i for i, key in enumerate(ordered)}

        window_len = max((win_end or 0) - (win_start or 0), 1)
        outside_len = max((span_end - span_start) - window_len, 1) if span_start is not None else 1

        hypotheses = []
        for key, members in groups.items():
            members.sort(key=lambda s: (LEVEL_RANK.get(s.level, 2), s.template.count), reverse=True)
            lead_stats = members[0]
            rule = lead_stats.rule
            live = sorted(i for m in members for i in m.template.record_ids if i >= 0)
            count = len(live)
            factors: list[dict] = []

            severity = max(_LEVEL_WEIGHT.get(m.level, 0.2) for m in members)
            rootness = rule.rootness if rule else 0.3
            if rule and rule.id != "app_exception":
                kind = "is usually a root cause" if rule.rootness >= 0.75 else (
                    "can be a cause or an effect" if rule.rootness >= 0.5 else "is usually a symptom of something else")
                factors.append({"key": "known", "label": f"Known failure: {rule.title.lower()}",
                                "detail": f"This kind of failure {kind}.", "weight": round(rootness, 2)})

            if key in position:
                first_ts = group_first[key][0]
                n = len(ordered)
                earliness = 1.0 if n == 1 else 1 - position[key] / (n - 1)
                after = n - 1 - position[key]
                if onset is not None and first_ts <= onset:
                    factors.append({"key": "first", "label": "Started before the errors spiked",
                                    "detail": f"First seen at {_fmt_time(first_ts)}, "
                                              f"{_fmt_delta(onset - first_ts)} before the spike.",
                                    "weight": round(earliness, 2)})
                elif position[key] == 0:
                    factors.append({"key": "first", "label": "First new failure in the incident",
                                    "detail": f"No other new warning or error appeared earlier "
                                              f"(first seen {_fmt_time(first_ts)}).", "weight": 1.0})
                if after:
                    factors.append({"key": "chain", "label": f"Followed by {after} other failure{'s' if after != 1 else ''}",
                                    "detail": "Failures that start after this one may be knock-on effects.",
                                    "weight": round(after / max(n - 1, 1), 2)})
                if position[key] > 0 and earliness < 0.5:
                    factors.append({"key": "late", "label": "Appeared late",
                                    "detail": f"{position[key]} other new failures started before it, "
                                              "so it is more likely an effect.", "weight": round(-(1 - earliness), 2)})
            elif any(m.template.id in chronic for m in members):
                earliness = 0.2
                factors.append({"key": "chronic", "label": "Was already happening before the incident",
                                "detail": f"First seen at {_fmt_time(lead_stats.first)}, long before things went wrong.",
                                "weight": -0.6})
            else:
                earliness = 0.1 if incident else 0.5

            concentration = 0.5
            if incident and span_start is not None:
                inside = sum(1 for i in live if in_window(self.records[i].ts))
                rate_in = inside / window_len
                rate_out = (count - inside) / outside_len
                concentration = rate_in / (rate_in + rate_out) if (rate_in + rate_out) else 0.5
                if concentration >= 0.8 and inside:
                    factors.append({"key": "focused", "label": "Concentrated in the incident",
                                    "detail": f"{inside} of {count} occurrences fall inside the incident window.",
                                    "weight": round(concentration, 2)})
                elif concentration < 0.6 and count - inside > 2:
                    factors.append({"key": "noise", "label": "Also happens outside the incident",
                                    "detail": f"{count - inside} of {count} occurrences are outside the incident, "
                                              "so it may be background noise.", "weight": round(concentration - 1, 2)})

            origin = 0.0
            if origin_file is not None and key in group_first and self.record_file[group_first[key][1]] == origin_file:
                origin = 1.0
                name = self.files[origin_file].name
                factors.append({"key": "origin", "label": f"Started in the first file to fail: {name}",
                                "detail": f"New failures in {name} began at {_fmt_time(file_onset[origin_file])}, "
                                          "before any other file.", "weight": 1.0})

            novelty = 0.5
            if self.baseline:
                base_count = sum(m.baseline_count for m in members)
                base_rate = base_count / max(self.baseline_total, 1)
                live_rate = count / max(len(self.records), 1)
                if base_count == 0:
                    novelty = 1.0
                    factors.append({"key": "new", "label": "New compared with the healthy run",
                                    "detail": "Never appears in the baseline logs.", "weight": 1.0})
                elif live_rate > base_rate * 3:
                    novelty = 0.75
                    factors.append({"key": "more", "label": f"{live_rate / base_rate:.0f}x more often than in the healthy run",
                                    "detail": f"{base_count} times in the baseline, {count} times here.", "weight": 0.75})
                else:
                    novelty = 0.0
                    factors.append({"key": "seen", "label": "Also normal in the healthy run",
                                    "detail": f"Seen {base_count} times in the baseline at a similar rate.",
                                    "weight": -0.8})

            if len(members) > 1:
                factors.append({"key": "corroborated", "label": f"Backed by {len(members)} different log patterns",
                                "detail": "Several distinct messages, often from different files, point to the same cause.",
                                "weight": round(min(1.0, len(members) / 5), 2)})
            root_exception = next((m.root_exception for m in members if m.root_exception), "")
            if root_exception:
                factors.append({"key": "causedby", "label": "Deepest error in the stack trace",
                                "detail": root_exception, "weight": 0.5})

            support = min(1.0, math.log10(count + 1) / 2)
            score = (0.20 * severity + 0.26 * rootness + 0.20 * earliness + 0.12 * concentration
                     + 0.07 * origin + 0.10 * novelty + 0.05 * support + 0.015 * min(len(members) - 1, 4))

            if rule and rule.id != "app_exception":
                title, summary, fixes, category = rule.title, rule.explanation, rule.fixes, rule.category
            else:
                exc = root_exception.split(":")[0].split(".")[-1] if root_exception else ""
                title = f"{exc}: {lead_stats.template.text}" if exc else lead_stats.template.text
                summary = rule.explanation if rule else "An error pattern that does not match a known signature."
                fixes = rule.fixes if rule else ["Read the first occurrence and its stack trace."]
                category = rule.category if rule else "Unclassified"
            times = [self.records[i].ts for i in live if self.records[i].ts is not None]
            first_record = group_first[key][1] if key in group_first else (live[0] if live else None)
            hypotheses.append({
                "id": key, "title": title, "category": category, "summary": summary, "fixes": fixes,
                "score": round(min(score, 1.0), 4), "templates": [m.template.id for m in members], "count": count,
                "first": min(times) if times else None, "last": max(times) if times else None,
                "files": sorted({self.record_file[i] for i in live}), "firstRecord": first_record,
                "evidence": self._evidence(live, first_record), "factors": factors,
                "custom": bool(rule and rule.custom), "level": max((m.level for m in members), key=lambda lv: LEVEL_RANK.get(lv, 2)),
                "emerging": key in position,
            })

        hypotheses.sort(key=lambda h: h["score"], reverse=True)
        top = hypotheses[:12]
        weights = [math.exp(10 * h["score"]) for h in top]
        total = sum(weights)
        for rank, (h, w) in enumerate(zip(top, weights), start=1):
            h["rank"] = rank
            h["likelihood"] = round(100 * w / total, 1)
            h["chain"] = self._chain(h)
        return top

    def _precursors(self, timeline: dict) -> list[dict]:
        """Events that appear for the first time shortly before the first failure: what changed."""
        first_failure = self._first_failure
        if first_failure is None or timeline["start"] is None:
            return []
        span = timeline["end"] - timeline["start"]
        lead = max(10 * timeline["bucket"], 0.15 * span)
        out = []
        for stats in self.stats.values():
            if stats.template.id in self._candidate_ids or stats.first is None:
                continue
            if not (first_failure - lead <= stats.first <= first_failure):
                continue
            # Must be new: nothing like it earlier in the logs, and not part of steady traffic.
            if stats.first - timeline["start"] < 0.05 * span or stats.template.count > 60:
                continue
            out.append({"template": stats.template.id, "first": stats.first, "count": stats.template.count,
                        "before": round(first_failure - stats.first, 3),
                        "beforeText": _fmt_delta(first_failure - stats.first) + " before",
                        "files": sorted(stats.files), "level": stats.level,
                        "record": next(i for i in stats.template.record_ids if i >= 0)})
        out.sort(key=lambda p: p["first"])
        return out[:8]

    def _evidence(self, live: list[int], first_record: int | None) -> list[int]:
        """The first new occurrence, then the first, middle and last ones, one per distinct pattern where possible."""
        picks: list[int] = [first_record] if first_record is not None else []
        seen_templates = {self.records[first_record].template_id} if first_record is not None else set()
        for i in live:
            tid = self.records[i].template_id
            if tid not in seen_templates:
                seen_templates.add(tid)
                picks.append(i)
        if live:
            picks += [live[0], live[len(live) // 2], live[-1]]
        return list(dict.fromkeys(picks))[:8]

    def _chain(self, hypothesis: dict) -> list[dict]:
        """New failure patterns that started after this cause, in order: the likely knock-on effects."""
        firsts = self._emerging_first
        own = set(hypothesis["templates"])
        start = min((firsts[t] for t in own if t in firsts), default=hypothesis["first"])
        if start is None:
            return []
        steps = []
        for tid, first in sorted(firsts.items(), key=lambda kv: kv[1]):
            if tid in own or first < start:
                continue
            stats = self.stats[tid]
            steps.append({"template": tid, "first": first, "delta": round(first - start, 3),
                          "deltaText": "+" + _fmt_delta(first - start), "count": stats.template.count,
                          "files": sorted(stats.files), "level": stats.level,
                          "title": stats.rule.title if stats.rule and stats.rule.id != "app_exception" else None})
            if len(steps) >= 10:
                break
        return steps

    # -------------------------------------------------------------- matching
    def _signatures(self) -> list[dict]:
        by_rule: dict[str, dict] = {}
        rules = {r.id: r for r in self.rules}
        for stats in self.stats.values():
            live = [i for i in stats.template.record_ids if i >= 0]
            if not live:
                continue
            for rule_id in stats.rules:
                rule = rules[rule_id]
                entry = by_rule.setdefault(rule_id, {
                    "id": rule_id, "title": rule.title, "category": rule.category,
                    "explanation": rule.explanation, "fixes": rule.fixes, "rootness": rule.rootness,
                    "custom": rule.custom, "count": 0, "templates": [], "files": set(), "first": None,
                    "patterns": rule.patterns,
                })
                entry["count"] += len(live)
                entry["templates"].append(stats.template.id)
                entry["files"].update(stats.files)
                if stats.first is not None and (entry["first"] is None or stats.first < entry["first"]):
                    entry["first"] = stats.first
        result = []
        for entry in by_rule.values():
            entry["files"] = sorted(entry["files"])
            result.append(entry)
        result.sort(key=lambda e: (e["custom"], e["id"] != "app_exception", e["count"]), reverse=True)
        return result

    def _traces(self) -> list[dict]:
        """Group records that share a request, trace or correlation ID, across files."""
        by_id: dict[str, list[int]] = defaultdict(list)
        for i, record in enumerate(self.records):
            for value in record.ids:
                by_id[value].append(i)
        limit = max(50, int(len(self.records) * 0.05))
        traces = []
        for value, idxs in by_id.items():
            if len(idxs) < 2 or len(idxs) > limit:
                continue
            files = sorted({self.record_file[i] for i in idxs})
            levels = [LEVEL_RANK.get(self.records[i].level, 2) for i in idxs]
            errors = sum(1 for lv in levels if lv >= LEVEL_RANK["ERROR"])
            warns = sum(1 for lv in levels if lv == LEVEL_RANK["WARN"])
            times = [self.records[i].ts for i in idxs if self.records[i].ts is not None]
            traces.append({
                "id": value, "records": idxs[:400], "count": len(idxs), "files": files,
                "errors": errors, "warnings": warns,
                "first": min(times) if times else None, "last": max(times) if times else None,
                "duration": (max(times) - min(times)) if times else 0,
                "templates": sorted({self.records[i].template_id for i in idxs}),
            })
        traces.sort(key=lambda t: (t["errors"] > 0, len(t["files"]), t["errors"], t["count"]), reverse=True)
        self.trace_stats = {"total": len(traces), "multiFile": sum(1 for t in traces if len(t["files"]) > 1),
                            "withErrors": sum(1 for t in traces if t["errors"])}
        # Keep mostly failing requests, plus some healthy ones to compare them with.
        failing = [t for t in traces if t["errors"]][:250]
        healthy = [t for t in traces if not t["errors"]][:300 - len(failing)]
        return failing + healthy

    def _compare(self) -> dict:
        live_total = max(len(self.records), 1)
        base_total = max(self.baseline_total, 1)
        new, gone, changed = [], [], []
        for stats in self.stats.values():
            live = sum(1 for i in stats.template.record_ids if i >= 0)
            base = stats.baseline_count
            live_rate = live / live_total * 10_000
            base_rate = base / base_total * 10_000
            entry = {"template": stats.template.id, "text": stats.template.text, "level": stats.level,
                     "live": live, "baseline": base, "liveRate": round(live_rate, 2), "baseRate": round(base_rate, 2)}
            if live and not base:
                new.append(entry)
            elif base and not live:
                gone.append(entry)
            elif live and base:
                ratio = live_rate / base_rate if base_rate else 0
                entry["ratio"] = round(ratio, 2)
                if ratio >= 2 or ratio <= 0.5:
                    changed.append(entry)
        rank = lambda e: (LEVEL_RANK.get(e["level"], 2), e["live"] or e["baseline"])
        new.sort(key=rank, reverse=True)
        gone.sort(key=lambda e: e["baseline"], reverse=True)
        changed.sort(key=lambda e: abs(math.log(max(e["ratio"], 1e-6))), reverse=True)
        return {"files": [{"name": f.name, "records": len(f.records)} for f in self.baseline],
                "records": self.baseline_total, "new": new[:300], "gone": gone[:300], "changed": changed[:300]}

    def _matches(self) -> list[dict]:
        out = []
        for i, pattern in enumerate(self.options.match_patterns):
            compiled = re.compile(pattern, re.IGNORECASE)
            hits = [idx for idx, record in enumerate(self.records) if compiled.search(self._match_text(record))]
            by_file = Counter(self.record_file[i] for i in hits)
            out.append({"pattern": pattern, "count": len(hits), "records": hits[:2000],
                        "byFile": {str(k): v for k, v in by_file.items()}})
        return out

    # ------------------------------------------------------------------ json
    def _meta(self) -> dict:
        files = []
        for i, parsed in enumerate(self.files):
            levels = Counter(r.level for r in parsed.records)
            times = [r.ts for r in parsed.records if r.ts is not None]
            files.append({"index": i, "name": parsed.name, "path": parsed.path, "format": parsed.format,
                          "lines": parsed.line_count, "records": len(parsed.records),
                          "first": min(times) if times else None, "last": max(times) if times else None,
                          "levels": {lv: levels.get(lv, 0) for lv in LEVELS},
                          "timestamped": round(parsed.timestamped, 3)})
        levels = Counter(r.level for r in self.records)
        times = [r.ts for r in self.records if r.ts is not None]
        from . import __version__
        return {"version": __version__, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "files": files, "records": len(self.records),
                "lines": sum(f.line_count for f in self.files),
                "levels": {lv: levels.get(lv, 0) for lv in LEVELS},
                "first": min(times) if times else None, "last": max(times) if times else None,
                "templates": sum(1 for s in self.stats.values() if any(i >= 0 for i in s.template.record_ids)),
                "baseline": [f.name for f in self.baseline], "matchPatterns": self.options.match_patterns}

    def _templates_json(self, timeline: dict) -> list[dict]:
        start, size = timeline["start"], timeline["bucket"]
        n = len(timeline["counts"])
        out = []
        for stats in self.stats.values():
            live = [i for i in stats.template.record_ids if i >= 0]
            if not live:
                continue
            spark = [0] * n
            if start is not None and size:
                for i in live:
                    ts = self.records[i].ts
                    if ts is not None:
                        spark[min(int((ts - start) // size), n - 1)] += 1
            out.append({"id": stats.template.id, "text": stats.template.text, "count": len(live),
                        "level": stats.level, "first": stats.first, "last": stats.last,
                        "files": sorted(stats.files), "rule": stats.rule.id if stats.rule else None,
                        "ruleTitle": stats.rule.title if stats.rule else None,
                        "baseline": stats.baseline_count if self.baseline else None,
                        "sample": live[0], "spark": spark})
        out.sort(key=lambda t: (LEVEL_RANK.get(t["level"], 2), t["count"]), reverse=True)
        return out

    def _records_json(self) -> list:
        keep = range(len(self.records))
        if len(self.records) > self.options.max_records:
            keep_set: set[int] = set()
            for i, record in enumerate(self.records):
                if LEVEL_RANK.get(record.level, 2) >= LEVEL_RANK["WARN"]:
                    keep_set.update(range(max(0, i - 3), min(len(self.records), i + 4)))
            budget = self.options.max_records - len(keep_set)
            if budget > 0:
                step = max(1, len(self.records) // budget)
                keep_set.update(range(0, len(self.records), step))
            keep = sorted(keep_set)[: self.options.max_records]
            self.truncated = True
        rows = []
        for i in keep:
            r = self.records[i]
            # The original line is only worth embedding when the message was rebuilt from it
            # (access logs, JSON); for plain text the message is already a slice of it.
            rebuilt = r.message not in r.raw or r.raw.lstrip().startswith("{")
            raw = r.raw[:4000] if rebuilt else None
            rows.append([i, self.record_file[i], r.ts, LEVEL_RANK.get(r.level, 2), r.template_id, r.line_no,
                         r.message[:4000], "\n".join(r.detail[:200])[:20000] if r.detail else None,
                         r.logger or None, r.ids or None, 1 if r.level_inferred else 0, raw])
        return rows


def analyse(files: list[ParsedFile], baseline: list[ParsedFile] | None = None,
            options: Options | None = None) -> dict:
    analysis = Analysis(files, baseline, options)
    result = analysis.run()
    result["meta"]["truncated"] = analysis.truncated
    result["meta"]["traceStats"] = analysis.trace_stats
    result["meta"]["embedded"] = len(result["records"])
    return result
