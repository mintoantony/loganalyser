import json

from loganalyser.rules import BUILTIN_RULES, load_rules
from loganalyser.templates import TemplateMiner, mask


def test_mask_keeps_route_shape_and_hides_values():
    text = mask("GET /api/orders/ord-123/status from 10.0.0.4:8080 took 35ms id=6f1c2d3e-0000-4000-8000-1234567890ab")
    assert "/api/orders/{id}/status" in text
    assert "<IP>" in text
    assert "<NUM>" in text
    assert "<UUID>" in text


def test_similar_messages_share_a_template():
    miner = TemplateMiner()
    a = miner.add("Connection to 10.0.0.4 failed after 3 retries for user alice", 0)
    b = miner.add("Connection to 10.0.0.9 failed after 5 retries for user bob", 1)
    c = miner.add("Cache warmed with 1500 entries", 2)
    assert a.id == b.id != c.id
    assert a.text == "Connection to <IP> failed after <NUM> retries for user <*>"
    assert a.count == 2


def test_pattern_keys_stay_exact():
    miner = TemplateMiner()
    ok = miner.add("GET /x/{id} -> 200", 0, masked=True)
    bad = miner.add("GET /x/{id} -> 503", 1, masked=True)
    assert ok.id != bad.id


def test_builtin_rules_recognise_common_failures():
    by_id = {r.id: r for r in BUILTIN_RULES}
    assert by_id["oom"].matches("java.lang.OutOfMemoryError: Java heap space")
    assert by_id["db_pool"].matches("HikariPool-1 - Connection is not available, request timed out after 30000ms.")
    assert by_id["disk_full"].matches("write failed: No space left on device")
    assert by_id["dns"].matches("java.net.UnknownHostException: orders-db")
    assert not by_id["oom"].matches("Order created")


def test_load_custom_rules(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": [{"id": "flag", "title": "Feature flag off", "patterns": "flag \\w+ disabled",
                                           "rootness": 0.9, "fixes": ["Turn it back on"]}]}), encoding="utf-8")
    rule = load_rules(path)[0]
    assert rule.custom and rule.title == "Feature flag off"
    assert rule.matches("flag checkout_v2 disabled by admin")
