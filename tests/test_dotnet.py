"""ASP.NET / Serilog logs written by one app to several files: day-first dates with offsets, the
"Logger | message | exception | {properties}" layout, indented property blocks, the same event in
several files, and one message ("Unhandled exception in circuit") thrown from different places."""

from datetime import datetime, timezone

from loganalyser.ai.advisor import build_evidence
from loganalyser.analysis import analyse
from loganalyser.parser import parse_lines
from loganalyser.rules import BUILTIN_RULES
from loganalyser.stacktrace import code_location


def utc(text):
    return datetime.fromisoformat(text).timestamp()


def trace(file, line, method):
    return (f"System.NullReferenceException: Object reference not set to an instance of an object.[CRLF]"
            f"   at System.Linq.Enumerable.Count[TSource](IEnumerable`1 source)[CRLF]"
            f"   at {method}() in {file}:line {line}[CRLF]"
            f"   at Microsoft.AspNetCore.Components.ComponentBase.CallStateHasChangedOnAsyncCompletion(Task task)")


def test_day_first_dates_with_an_offset():
    lines = ["15/06/2026 16:29:06.904 +01:00 [ERR] boom", "08/06/2026 09:00:00.000 +01:00 [INF] earlier"]
    records = parse_lines(lines, "app.txt").records
    assert records[0].ts == utc("2026-06-15T15:29:06.904+00:00")
    assert records[1].ts == utc("2026-06-08T08:00:00+00:00")
    assert records[0].message == "boom"


def test_ambiguous_dates_follow_the_date_in_the_file_name():
    line = ["08/06/2026 16:56:21.399 +01:00 [ERR] boom"]
    assert parse_lines(line, "Web.App.20260608.txt").records[0].ts == utc("2026-06-08T15:56:21.399+00:00")
    assert parse_lines(line, "web-2026-08-06.log").records[0].ts == utc("2026-08-06T15:56:21.399+00:00")


def test_month_first_dates_still_work():
    assert parse_lines(["06/15/2026 16:29:06 [ERR] boom"], "a.log").records[0].ts == utc("2026-06-15T16:29:06+00:00")


def test_pipe_layout_gives_logger_message_exception_and_properties():
    line = ('12/06/2026 09:57:49.300 +01:00 [ERR] Shop.Web.AddressLookup | Search failed | '
            + trace(r"D:\src\Shop.Web\AddressLookup.razor.cs", 129, "Shop.Web.AddressLookup.SearchAsync")
            + ' | {"SourceContext":"Shop.Web.AddressLookup","RequestId":"40000005-0000-fc00-b63f-84710c7967bb"}')
    record = parse_lines([line], "debug.txt").records[0]
    assert (record.level, record.logger, record.message) == ("ERROR", "Shop.Web.AddressLookup", "Search failed")
    assert record.detail[0].startswith("System.NullReferenceException")
    assert record.fields["RequestId"] == "40000005-0000-fc00-b63f-84710c7967bb"


def test_indented_property_blocks_stay_with_their_event():
    lines = ["12/06/2026 10:40:40.494 +01:00 [ERR] Vite.Manifest | The manifest file was not found.",
             "    Additional Properties:",
             '    {"EventId":{"Id":6},"SourceContext":"Vite.Manifest","RequestPath":"/"}',
             "    Exception:",
             "================================",
             "12/06/2026 10:59:23.508 +01:00 [ERR] Vite.Manifest | The manifest file was not found."]
    records = parse_lines(lines, "exceptions.txt").records
    assert len(records) == 2
    assert any('"EventId"' in d for d in records[0].detail)


def test_code_location_skips_framework_frames():
    record = parse_lines(["12/06/2026 09:57:49.300 +01:00 [ERR] A.B | Failed | "
                          + trace(r"D:\src\Web\AddressLookup.razor.cs", 129, "Web.AddressLookup.SearchAsync")],
                         "a.txt").records[0]
    where = code_location(record)
    assert (where.exception, where.line, where.method) == ("NullReferenceException", 129, "Web.AddressLookup.SearchAsync")
    assert where.file.endswith("AddressLookup.razor.cs")


def test_code_location_in_python_is_the_deepest_own_frame():
    record = parse_lines(["2026-06-12 09:57:49,300 ERROR worker: task failed",
                          "Traceback (most recent call last):",
                          '  File "/app/worker/tasks.py", line 88, in resize',
                          '  File "/app/worker/images.py", line 12, in load',
                          '  File "/usr/lib/python3.12/site-packages/PIL/Image.py", line 3300, in open',
                          "OSError: cannot identify image file"], "w.log").records[0]
    where = code_location(record)
    assert (where.exception, where.file, where.line) == ("OSError", "/app/worker/images.py", 12)


def _two_sinks():
    """The same app writing to an app file (no stack traces) and an errors file (with them)."""
    app, errors = [], []
    crashes = [("12/06/2026 11:57:23.211", r"D:\src\Web\Login.razor.cs", 40, "Web.Login.OnInit"),
               ("15/06/2026 16:29:09.690", r"D:\src\Web\AddressLookup.razor.cs", 129, "Web.AddressLookup.SearchAsync"),
               ("15/06/2026 16:34:12.108", r"D:\src\Web\AddressLookup.razor.cs", 129, "Web.AddressLookup.SearchAsync")]
    for stamp, file, line, method in crashes:
        head = f"{stamp} +01:00 [ERR] Microsoft.AspNetCore.Components.Server.Circuits.CircuitHost | "
        app.append(f"{stamp} +01:00 [ERR] Unhandled exception in circuit 'PFsN0HIxlN3W_cxjSwbOHvOs72YIQ6iWXa'.")
        errors.append(head + "Unhandled exception in circuit 'PFsN0HIxlN3W_cxjSwbOHvOs72YIQ6iWXa'. | "
                      + trace(file, line, method) + " | {}")
    files = [parse_lines(app, "Web.App.txt"), parse_lines(errors, "Web.Exceptions.txt")]
    for f in files:
        f.path = f.name
    return analyse(files)


def test_an_event_in_several_files_is_counted_once():
    result = _two_sinks()
    assert result["meta"]["records"] == 3
    assert result["meta"]["copiesCounted"] == 3


def test_one_message_thrown_from_two_places_is_two_patterns():
    result = _two_sinks()
    texts = sorted(t["text"] for t in result["templates"])
    assert texts == ["Unhandled exception in circuit '<ID>'. [NullReferenceException at AddressLookup.razor.cs:L129]",
                     "Unhandled exception in circuit '<ID>'. [NullReferenceException at Login.razor.cs:L40]"]
    where = result["meta"]["codeLocations"]
    assert [(w["line"], w["count"], w["days"]) for w in where] == [(129, 2, ["2026-06-15"]), (40, 1, ["2026-06-12"])]


def test_a_logged_unhandled_exception_is_not_a_process_crash():
    crash = next(r for r in BUILTIN_RULES if r.id == "crash")
    assert not crash.matches("Unhandled exception in circuit 'abc'.")
    assert not crash.matches("An unhandled exception has occurred while executing the request.")
    assert crash.matches("Unhandled exception. System.InvalidOperationException: boom")


def test_evidence_can_be_kept_under_a_size():
    result = _two_sinks()
    full, _ = build_evidence(result, max_lines=50)
    small, cited = build_evidence(result, max_lines=50, max_chars=len(full) - 200)
    assert len(small) < len(full) and cited
    assert "more lines left out" in small
