"""The second test incident (scripts/make_test_incident.py): a full disk behind loud Redis and HTTP errors.

Several seeds, because a ranking that holds for one random draw of the logs but not the next is not a
ranking to trust.
"""

import importlib.util
from pathlib import Path

import pytest

from loganalyser.analysis import analyse
from loganalyser.cli import _parse_all, collect

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "make_test_incident.py"


def _generator():
    spec = importlib.util.spec_from_file_location("make_test_incident", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module", params=[31, 5, 77])
def media(request, tmp_path_factory):
    out = tmp_path_factory.mktemp(f"media-{request.param}")
    _generator().generate(out, seed=request.param)
    files = _parse_all(collect([str(out / "incident")]), "read")
    baseline = _parse_all(collect([str(out / "baseline")]), "baseline")
    return files, analyse(files, baseline)


def _text(result, template_id):
    return next(t["text"] for t in result["templates"] if t["id"] == template_id)


def _names(result, file_indexes):
    return {result["meta"]["files"][i]["name"] for i in file_indexes}


def test_full_disk_ranks_first(media):
    _, result = media
    assert result["causes"][0]["id"] == "disk_full"
    assert {"media-service.log", "redis-server.log", "worker.log"} <= _names(result, result["causes"][0]["files"])


def test_files_without_an_extension_are_read(media):
    files, _ = media
    assert "syslog" in {Path(f.path).name for f in files}


def test_folders_pick_text_logs_without_an_extension(tmp_path):
    (tmp_path / "messages").write_text("Oct 28 14:31:07 host app: started\n", encoding="utf-8")
    (tmp_path / "messages.1").write_text("Oct 27 14:31:07 host app: started\n", encoding="utf-8")
    (tmp_path / "core").write_bytes(b"\x7fELF\x00\x00\x01")
    (tmp_path / "notes.md").write_text("not a log\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert sorted(p.name for p in collect([str(tmp_path)])) == ["messages", "messages.1"]


def test_redis_lines_have_times(media):
    files, _ = media
    redis = next(f for f in files if f.name.endswith("redis-server.log"))
    assert redis.timestamped == 1.0
    assert all(r.logger == "redis" and not r.message.startswith(("#", "*")) for r in redis.records)


def test_pino_request_ids_link_the_api_to_nginx(media):
    _, result = media
    trace = next(t for t in result["traces"] if t["id"] == "req-7c1e9a40d2")
    assert {"access.log", "api.log"} <= _names(result, trace["files"])
    assert trace["errors"]


def test_the_deploy_shows_as_what_changed(media):
    _, result = media
    texts = [_text(result, p["template"]) for p in result["incident"]["precursors"]]
    assert any("set to DEBUG" in t for t in texts)
    assert not any("Certificate for" in t or "CMD (" in t for t in texts)


def test_different_messages_from_different_services_stay_apart(media):
    _, result = media
    texts = [t["text"] for t in result["templates"]]
    assert any(t.startswith("Failed to write thumbnail") for t in texts)
    assert any(t.startswith("Failed to enqueue thumbnail job") for t in texts)
