import json
import re

from loganalyser import report
from loganalyser.analysis import analyse
from loganalyser.cli import main
from loganalyser.parser import parse_lines


def embedded_data(page: str) -> dict:
    match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', page, re.S)
    return json.loads(match.group(1))


def test_log_text_cannot_break_out_of_the_page():
    lines = ["2026-10-27 09:00:00 ERROR app - bad input </script><script>alert(1)</script> <!-- x"]
    page = report.render(analyse([parse_lines(lines, "app.log")]))
    assert page.count("</script>") == 2  # only the page's own two script blocks
    data = embedded_data(page)
    assert "</script><script>alert(1)" in data["records"][0][6]


def test_cli_demo_writes_a_report(tmp_path, capsys):
    out = tmp_path / "report.html"
    assert main(["demo", "--folder", str(tmp_path / "logs"), "-o", str(out)]) == 0
    page = out.read_text(encoding="utf-8")
    assert "<title>Log analysis: Database connection pool exhausted</title>" in page
    assert embedded_data(page)["causes"][0]["id"] == "db_pool"
    assert "Database connection pool exhausted" in capsys.readouterr().err


def test_cli_analyse_folder_with_json_output(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("2026-10-27 09:00:00 ERROR app - java.lang.OutOfMemoryError: Java heap space\n", encoding="utf-8")
    out, findings = tmp_path / "r.html", tmp_path / "f.json"
    assert main(["analyse", str(logs), "-o", str(out), "--json", str(findings)]) == 0
    data = json.loads(findings.read_text(encoding="utf-8"))
    assert data["causes"][0]["id"] == "oom"
    assert "records" not in data
