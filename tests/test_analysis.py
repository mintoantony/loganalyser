import json

import pytest

from loganalyser.analysis import Options, analyse
from loganalyser.parser import parse_file, parse_lines
from loganalyser.rules import load_rules
from loganalyser.samples import generate


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    paths = generate(tmp_path_factory.mktemp("demo"))
    files = [parse_file(p) for p in paths["incident"]]
    baseline = [parse_file(p) for p in paths["baseline"]]
    return analyse(files, baseline, Options(match_patterns=["nightly-export"]))


def templates(result):
    return {t["id"]: t for t in result["templates"]}


def test_finds_the_real_cause(demo):
    top = demo["causes"][0]
    assert top["id"] == "db_pool"
    assert top["likelihood"] > 50
    keys = {f["key"] for f in top["factors"]}
    assert {"known", "first", "origin", "new"} <= keys


def test_background_noise_is_not_blamed(demo):
    noise = next(c for c in demo["causes"] if "smtp" in templates(demo)[c["templates"][0]]["text"])
    assert noise["rank"] > 3
    assert any(f["key"] == "chronic" for f in noise["factors"])


def test_symptoms_rank_below_the_cause_and_follow_it(demo):
    ranks = {c["id"]: c["rank"] for c in demo["causes"]}
    for symptom in ("http_5xx", "circuit_open", "upstream_5xx"):
        assert ranks[symptom] > ranks["db_pool"]
    chain_titles = {s["title"] for s in demo["causes"][0]["chain"]}
    assert "Circuit breaker open" in chain_titles


def test_reports_what_changed_just_before(demo):
    texts = [templates(demo)[p["template"]]["text"] for p in demo["incident"]["precursors"]]
    assert any(t.startswith("Job nightly-export started") for t in texts)


def test_links_events_across_files_by_id(demo):
    assert demo["meta"]["traceStats"]["multiFile"] > 100
    failing = next(t for t in demo["traces"] if t["errors"])
    assert len(failing["files"]) >= 2


def test_compares_with_the_healthy_run(demo):
    new_texts = [n["text"] for n in demo["compare"]["new"]]
    assert any("Connection is not available" in t for t in new_texts)
    assert not any("smtp-relay" in t for t in new_texts)


def test_match_patterns_are_searches_not_causes(demo):
    assert demo["matches"][0]["count"] == 2
    assert all(not c["id"].startswith("match") for c in demo["causes"])


def test_clean_logs_have_no_causes():
    lines = [f"2026-10-27 09:00:{i:02d} INFO worker - processed batch {i}" for i in range(30)]
    result = analyse([parse_lines(lines, "ok.log")])
    assert result["causes"] == []
    assert result["incident"] is None


def test_custom_rule_wins_over_builtin(tmp_path):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([{"id": "pay", "title": "Payment provider down", "patterns": ["payment gateway"],
                                       "rootness": 0.9}]), encoding="utf-8")
    lines = [f"2026-10-27 09:00:{i:02d} INFO app - ok" for i in range(40)]
    lines += [f"2026-10-27 09:01:{i:02d} ERROR app - payment gateway timed out" for i in range(20)]
    result = analyse([parse_lines(lines, "app.log")], options=Options(rules=load_rules(rules_file)))
    assert result["causes"][0]["title"] == "Payment provider down"
    assert result["causes"][0]["custom"]


def test_given_incident_window_is_used():
    lines = [f"2026-10-27 09:{m:02d}:00 ERROR app - disk write failed: No space left on device" for m in range(0, 50, 5)]
    result = analyse([parse_lines(lines, "app.log")], options=Options(incident_start=1793091600, incident_end=1793094000))
    assert result["incident"]["source"] == "given"
    assert result["causes"][0]["id"] == "disk_full"


def test_large_input_is_trimmed_for_the_report_but_keeps_errors():
    lines = [f"2026-10-27 09:{i // 60 % 60:02d}:{i % 60:02d} INFO app - tick {i}" for i in range(3000)]
    lines.insert(1500, "2026-10-27 09:25:00 ERROR app - Connection refused")
    result = analyse([parse_lines(lines, "app.log")], options=Options(max_records=500))
    assert result["meta"]["truncated"]
    assert len(result["records"]) <= 500
    assert any(r[6] == "Connection refused" for r in result["records"])
