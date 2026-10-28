import re

import anyio
import pytest

pytest.importorskip("mcp.server.mcpserver")

from mcp import Client  # noqa: E402

from loganalyser import mcp_server  # noqa: E402
from loganalyser.desktop import runs  # noqa: E402
from loganalyser.samples import generate  # noqa: E402


def call(tool: str, **arguments) -> tuple[str, bool]:
    async def go():
        async with Client(mcp_server.server) as client:
            result = await client.call_tool(tool, arguments)
            return "\n".join(block.text for block in result.content if hasattr(block, "text")), bool(result.is_error)
    return anyio.run(go)


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    folder = tmp_path_factory.mktemp("demo")
    generate(folder)
    return folder


@pytest.fixture
def run_id(demo):
    text, error = call("analyse_logs", paths=[str(demo / "incident")], baseline=[str(demo / "baseline")],
                       match=["503"])
    assert not error, text
    return re.search(r"Run ([0-9a-f]{12})", text).group(1)


def test_lists_tools_and_prompt():
    async def go():
        async with Client(mcp_server.server) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            prompts = {p.name for p in (await client.list_prompts()).prompts}
            return tools, prompts
    tools, prompts = anyio.run(go)
    assert tools == {"analyse_logs", "explain_cause", "get_evidence", "search_logs", "get_log_lines",
                     "follow_request", "list_analyses", "open_report"}
    assert "investigate" in prompts


def test_analyse_finds_the_demo_cause_and_saves_the_run(demo):
    text, error = call("analyse_logs", paths=[str(demo / "incident")], baseline=[str(demo / "baseline")])
    assert not error
    assert "Most likely cause:" in text and "pool" in text.lower()
    run = re.search(r"Run ([0-9a-f]{12})", text).group(1)
    assert runs.report_path(run).is_file()
    assert run in call("list_analyses")[0]


def test_follow_up_tools(run_id):
    text, error = call("explain_cause", run_id=run_id, rank=1)
    assert not error and "Signals:" in text and "Evidence:" in text
    line = int(re.search(r"^L(\d+) \|", text, re.M).group(1))

    around, error = call("get_log_lines", run_id=run_id, line=line, before=3, after=3)
    assert not error and f"> L{line} |" in around

    found, _ = call("search_logs", run_id=run_id, query="hikari", min_level="WARN", limit=5)
    assert "matching lines" in found and found.count("\nL") <= 5

    pack, _ = call("get_evidence", run_id=run_id, max_lines=40)
    assert "# Candidate causes" in pack and "# Log lines" in pack

    failing, _ = call("follow_request", run_id=run_id, request_id="")
    request = re.search(r"^  (\S+): \d+ events", failing, re.M).group(1)
    trace, _ = call("follow_request", run_id=run_id, request_id=request)
    assert "events in" in trace


def test_bad_input_comes_back_as_a_tool_error(tmp_path, run_id):
    text, error = call("analyse_logs", paths=[str(tmp_path / "nope")])
    assert error and "Nothing found" in text
    text, error = call("explain_cause", run_id="000000000000")
    assert error and "list_analyses" in text
    text, error = call("search_logs", run_id=run_id, query="(", regex=True)
    assert error and "regular expression" in text
    text, error = call("explain_cause", run_id=run_id, rank=99)
    assert error and "rank 1 to" in text


def test_answers_hide_personal_data_by_default(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("2026-01-01 10:00:00 INFO start\n"
                   "2026-01-01 10:00:01 ERROR Login failed for jane.doe@example.com from 10.1.2.3\n"
                   "2026-01-01 10:00:02 ERROR Login failed for jane.doe@example.com from 10.1.2.3\n", encoding="utf-8")
    text, error = call("analyse_logs", paths=[str(log)])
    assert not error
    run = re.search(r"Run ([0-9a-f]{12})", text).group(1)
    found, _ = call("search_logs", run_id=run, query="login")
    assert "jane.doe@example.com" not in found and "10.1.2.3" not in found
