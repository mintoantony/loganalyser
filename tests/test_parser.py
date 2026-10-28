import gzip
from datetime import datetime, timezone

from loganalyser.parser import parse_file, parse_lines


def ts(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


def test_log4j_style_line():
    parsed = parse_lines(["2026-10-27 09:30:41,016 ERROR [http-nio-8080-exec-3] com.shop.orders.ErrorHandler - Request failed"], "a.log")
    record = parsed.records[0]
    assert record.level == "ERROR"
    assert record.logger == "com.shop.orders.ErrorHandler"
    assert record.fields["thread"] == "http-nio-8080-exec-3"
    assert record.message == "Request failed"
    assert record.ts == ts("2026-10-27 09:30:41.016")


def test_spring_boot_line_drops_pid():
    parsed = parse_lines(["2026-10-27T09:00:01.123Z  INFO 4127 --- [main] c.s.o.OrdersApplication : Started in 6.4 seconds"], "a.log")
    record = parsed.records[0]
    assert record.level == "INFO"
    assert record.logger == "c.s.o.OrdersApplication"
    assert record.message == "Started in 6.4 seconds"


def test_postgres_line_with_utc_suffix():
    parsed = parse_lines(["2026-10-27 09:31:02.118 UTC [2231] FATAL:  sorry, too many clients already"], "pg.log")
    record = parsed.records[0]
    assert record.level == "FATAL"
    assert record.message == "sorry, too many clients already"
    assert record.ts == ts("2026-10-27 09:31:02.118")


def test_postgres_duration_is_not_taken_as_logger():
    parsed = parse_lines(["2026-10-27 09:31:02.118 UTC [2231] LOG:  duration: 48211.551 ms  statement: SELECT 1"], "pg.log")
    assert parsed.records[0].message.startswith("duration: 48211.551 ms")


def test_json_line_with_numeric_level_and_ids():
    line = '{"time":1793093430123,"level":50,"msg":"Upstream failed","traceId":"abc123def456","error":{"status":503}}'
    record = parse_lines([line], "svc.jsonl").records[0]
    assert record.level == "ERROR"
    assert record.message == "Upstream failed"
    assert record.ids == ["abc123def456"]
    assert abs(record.ts - 1793093430.123) < 1e-6
    assert record.detail == ['{"status": 503}']


def test_access_log_level_from_status_and_pattern_key():
    line = '10.0.0.1 - - [27/Oct/2026:09:30:41 +0000] "GET /api/orders/ord-9786?x=1 HTTP/1.1" 503 167 "-" "curl/8" rt=30.012 request_id=4bf92f3577b34da6'
    parsed = parse_lines([line], "access.log")
    record = parsed.records[0]
    assert parsed.format == "access"
    assert record.level == "ERROR"
    assert record.fields["pattern"] == "GET /api/orders/{id} -> 503"
    assert record.fields["response_time"] == 30.012
    assert "4bf92f3577b34da6" in record.ids


def test_syslog_line():
    record = parse_lines(["Oct 27 09:12:01 web-1 kernel: Out of memory: Killed process 4242 (java)"], "syslog", 2026).records[0]
    assert record.logger == "kernel"
    assert record.fields["host"] == "web-1"
    assert record.ts == ts("2026-10-27 09:12:01")
    assert record.level == "ERROR"  # inferred from the text
    assert record.level_inferred


def test_java_stack_trace_is_folded_into_its_event():
    lines = [
        "2026-10-27 09:30:41,016 ERROR [t1] com.x.Handler - Request failed",
        "java.lang.IllegalStateException: boom",
        "\tat com.x.Handler.run(Handler.java:10)",
        "Caused by: java.sql.SQLException: no connection",
        "\t... 12 more",
        "2026-10-27 09:30:42,000 INFO  [t1] com.x.Handler - Next",
    ]
    records = parse_lines(lines, "a.log").records
    assert len(records) == 2
    assert len(records[0].detail) == 4
    assert records[1].message == "Next"


def test_python_traceback_is_folded():
    lines = [
        "2026-10-27 09:30:41,016 ERROR app: crashed",
        "Traceback (most recent call last):",
        '  File "app.py", line 3, in <module>',
        "    main()",
        "KeyError: 'DATABASE_URL'",
    ]
    records = parse_lines(lines, "a.log").records
    assert len(records) == 1
    assert records[0].detail[-1] == "KeyError: 'DATABASE_URL'"


def test_file_without_timestamps_keeps_lines_apart():
    records = parse_lines(["starting worker", "worker failed: connection refused", "retrying"], "plain.txt").records
    assert [r.message for r in records] == ["starting worker", "worker failed: connection refused", "retrying"]
    assert records[1].level == "ERROR"


def test_python_logging_default_format():
    record = parse_lines(["WARNING:urllib3.connectionpool:Retrying after connection broken"], "a.log").records[0]
    assert record.level == "WARN"
    assert record.logger == "urllib3.connectionpool"


def test_reads_gzip(tmp_path):
    path = tmp_path / "app.log.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("2026-10-27 09:00:00 ERROR something broke\n")
    parsed = parse_file(path)
    assert parsed.records[0].level == "ERROR"


def test_level_words_inside_the_message_stay_in_it():
    lines = ["Oct 28 14:20:01 media-01 disk-monitor[812]: /var/data usage 91% (warning above 85%)",
             "2026-10-28 14:20:01 Connection error while saving order",
             "2026-10-28 14:20:02 error: payment declined",
             "2026-10-28 14:20:03 [main] WARN com.shop.Cache - cache nearly full",
             "2026-10-28 14:20:04 <error> disk read failed"]
    got = [(r.level, r.message) for r in parse_lines(lines, "a.log").records]
    assert got == [("WARN", "/var/data usage 91% (warning above 85%)"),
                   ("ERROR", "Connection error while saving order"),
                   ("ERROR", "payment declined"),
                   ("WARN", "cache nearly full"),
                   ("ERROR", "disk read failed")]
