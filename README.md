# LogAnalyser

Point it at the logs from a failure. It tells you the most likely cause, shows the evidence, and writes
one interactive HTML report you can open in any browser or send to a colleague. Python 3.11+, no dependencies.

```bash
# See it work on a made-up incident (writes demo-logs/ and demo-report.html)
python -m loganalyser demo --open

# Your own logs: files, folders or patterns, any mix of formats
python -m loganalyser analyse logs/ -o report.html --open

# Compare with logs from a time when things worked
python -m loganalyser analyse failing/ --baseline healthy/ -o report.html
```

`pip install -e .` also gives you a `loganalyser` command.

## Desktop app

The same analyser in a window, for Windows and macOS. Drop a folder or files and watch the analysis run.
You can add an AI second opinion, and past analyses are kept so you can reopen them.

```bash
pip install -e ".[desktop]"
python -m loganalyser.desktop          # or: loganalyser-app
python -m loganalyser.desktop --browser   # same app in your browser, if no native window is available
```

Installable builds:

| Platform | How | Result |
|---|---|---|
| Windows | `powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1` | `dist\LogAnalyser\LogAnalyser.exe`, a portable zip, and, if [Inno Setup](https://jrsoftware.org/isinfo.php) is installed, `LogAnalyser-1.2.0-Windows-Setup.exe` |
| macOS (run on a Mac) | `bash packaging/build_mac.sh` | `dist/LogAnalyser.app`, an installer wizard `LogAnalyser-1.2.0-macOS-Installer.pkg`, and a drag-to-Applications `.dmg` |
| Both, in CI | push a `v*` tag or run the *Build desktop app* workflow (`.github/workflows/desktop.yml`) | installers as build artifacts |

The Windows installer is an ordinary setup wizard, made for people with no technical background:

1. **Welcome**
2. **Checking your computer**: a tick or a cross for each requirement:
   - Windows 10 or 11 (64-bit)
   - enough disk space
   - the Microsoft WebView2 Runtime
   - Ollama, which is optional and only noted
3. **Ready**, then **Installing**. If WebView2 is missing, Setup downloads it from Microsoft and
   installs it, with a progress bar. If that fails, the app still installs and opens in the web
   browser instead.
4. **Finish**: *Open LogAnalyser now* is ticked, with a line on how to start.

It installs for the current user without admin rights. A Start menu entry and an optional desktop
shortcut are added. Uninstalling asks whether to also remove saved analyses and settings, and
defaults to keeping them. If you choose to remove them, they go to the Recycle Bin, never a
permanent delete, so you can restore them. To try the WebView2 download on a PC that already has it, run the installer
with `/WEBVIEW2=missing`.

On a Mac there are two ways to install:

- **The installer wizard (`.pkg`).** It uses macOS's own installer: Welcome, then the checks, then
  Install, then a Summary on how to start.
  - The checks are macOS 11 or later, a Mac with Apple silicon, and about 300 MB free.
  - If one fails, it stops with a plain explanation. An Intel Mac, for example, is told it needs
    the Intel version.
  - It puts LogAnalyser in Applications. macOS asks for the person's password, as for any app
    installed there.
  - Nothing else is needed: macOS already has what the app uses to show its window.
- **The disk image (`.dmg`).** It opens a window with an arrow from LogAnalyser to the Applications
  folder, for people used to dragging apps in.

To remove the app on a Mac, drag it to the Trash. Saved analyses stay in
`~/Library/Application Support/LogAnalyser`.

The builds are not code-signed, so Windows SmartScreen and macOS Gatekeeper warn the first time you
open them. On a Mac, try to open the app once, then go to *System Settings > Privacy & Security* and
click *Open Anyway* (on macOS 14 and earlier, right-clicking the app and choosing *Open* also works). To share widely, sign with your organisation's
certificate (Authenticode on Windows, Developer ID plus notarisation on macOS). Windows needs the
WebView2 runtime, which Windows 10 and 11 already include.

## AI second opinion

The built-in analysis always runs first and needs no key. Optionally, an LLM then reads the same
incident and gives its own verdict, in the same shape: root cause, confidence, the evidence lines it
relies on, how the incident unfolded, contributing factors, alternatives it ruled out, and what to do
now, next and later. The report shows whether the AI agrees with the built-in ranking. Every line the
AI cites opens in the Explorer, so you can check it.

| Provider | What you need |
|---|---|
| Claude (Anthropic API) | API key. Uses Claude Opus 5.5 by default, through the official `anthropic` SDK |
| OpenAI | API key and a model (use *Load list*) |
| Google Gemini | API key and a model |
| Microsoft Azure AI Foundry | Endpoint, deployment name, key; API version (`2024-10-21`, or `v1` for the newer endpoint) |
| OpenRouter | API key and any model it offers |
| Ollama | Nothing leaves your machine: start Ollama and pick an installed model |
| Other OpenAI-compatible server | Base URL ending in `/v1` (LM Studio, vLLM, LiteLLM and similar) |

Set the provider up in the app under **Settings**, where *Test connection* checks it. API keys are kept
in the system keychain (Windows Credential Manager, macOS Keychain). Keys can also come from
environment variables: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `AZURE_OPENAI_API_KEY`
or `OPENROUTER_API_KEY`.

**What gets sent.** The LLM never sees your raw files. It gets an evidence pack: the overview, the
built-in candidates with their reasons, the failure patterns, and up to 300 log lines (you can change
this) chosen around the failures. By default, emails, IP addresses, passwords, tokens, keys and user
names are replaced before anything leaves your computer. Request and trace IDs are kept so the AI can
follow them. If the AI step fails, the report is still produced, with the reason.

From the command line (uses the app's saved settings unless overridden):

```bash
python -m loganalyser analyse logs/ --ai
python -m loganalyser analyse logs/ --ai --ai-provider ollama --ai-model qwen2.5-coder:7b --ai-lines 80
```

## Use it from Claude, Copilot and other AI tools (MCP)

LogAnalyser is also an [MCP](https://modelcontextprotocol.io) server, so any AI tool that supports MCP
(Claude Desktop, Claude Code, GitHub Copilot in VS Code, Cursor and others) can analyse logs with it.
Ask *"why did the orders service fail? the logs are in D:\incidents\0412"* and the assistant runs the
analysis, reads the evidence and answers with the lines that prove it.

| Tool | What it does |
|---|---|
| `analyse_logs` | Analyses files or folders (with an optional healthy run, patterns and rules) and returns the ranked causes, what changed just before, and the report path |
| `explain_cause` | Everything behind one cause: signals, patterns, evidence lines with stack traces, what followed, what to try |
| `get_evidence` | The whole incident in one text, for the assistant to form its own view |
| `search_logs` | Text or regex search, by level, file or pattern |
| `get_log_lines` | The lines around any cited line (`L1234`) |
| `follow_request` | One request, trace or order ID followed across all files |
| `list_analyses` | Past runs, including ones made in the desktop app |
| `open_report` | Opens the interactive report in the browser or in the desktop app |

There is also an *Investigate an incident* prompt. Runs are saved to the same history as the desktop
app, so you can start in a chat and carry on in the app. Log text in the answers follows the app's
privacy setting: emails, IPs, tokens and user names are hidden unless you switch that off.

**The command to give your AI tool**

| You have | Command |
|---|---|
| The Windows installer | `%LOCALAPPDATA%\Programs\LogAnalyser\LogAnalyser.exe --mcp` (or under `C:\Program Files\LogAnalyser` if installed for all users) |
| The Mac app | `/Applications/LogAnalyser.app/Contents/MacOS/LogAnalyser --mcp` |
| The source | `pip install -e ".[mcp]"`, then `loganalyser-mcp` (or `python -m loganalyser mcp`) |

Use the full path in the settings below. These examples use the source install in this folder:

**Claude Desktop**: *Settings > Developer > Edit config*, then restart Claude:

```json
{
  "mcpServers": {
    "loganalyser": {
      "command": "D:\\VanguardProjects\\Agents\\LogAnalyser\\.venv\\Scripts\\loganalyser-mcp.exe"
    }
  }
}
```

**Claude Code**: see [Use it in all your Claude Code projects](#use-it-in-all-your-claude-code-projects) below.

**GitHub Copilot in VS Code**: run *MCP: Add Server* from the command palette, or put this in
`.vscode/mcp.json` (one project) or your user `mcp.json` (all projects), then use Copilot Chat in
*Agent* mode:

```json
{
  "servers": {
    "loganalyser": {
      "type": "stdio",
      "command": "D:\\VanguardProjects\\Agents\\LogAnalyser\\.venv\\Scripts\\loganalyser-mcp.exe"
    }
  }
}
```

For the installed app, use the `LogAnalyser.exe` path as `command` and add `"args": ["--mcp"]`.

### The log investigator agent (Claude Code, Copilot, Codex)

This folder includes a `log-investigator` agent for each tool, all with the same instructions. Ask
*"why did it break? logs in D:\incidents\0412"*. The agent runs the analysis and checks the top cause
against the log lines instead of repeating it. It also follows a failing request across services.
It answers with:

- the root cause
- the lines that prove it
- how it unfolded
- what it ruled out
- what to do now and next

| Tool | Agent | Server config | First time |
|---|---|---|---|
| Claude Code | `.claude/agents/log-investigator.md` | `.mcp.json` | Approve the `loganalyser` server when asked |
| Copilot CLI | `.github/agents/log-investigator.agent.md` | `.mcp.json` | Pick it with `/agent`, or start with `copilot --agent log-investigator` |
| Copilot in VS Code | `.github/agents/log-investigator.agent.md` | `.vscode/mcp.json` | Start the server from `mcp.json`, then pick *log-investigator* in the Chat agent list |
| Codex (CLI, app, IDE) | `.codex/agents/log-investigator.toml`, plus the skill `.agents/skills/investigate-logs` | `.codex/config.toml` | Trust the project in Codex; then use `$investigate-logs`, or ask Codex to use the log-investigator agent |

The instructions live in `.claude/agents/log-investigator.md`. After changing them, run
`python scripts/sync_agents.py` to update the Copilot and Codex copies (a test fails if you forget).
The server path in the three config files points to this folder's `.venv`; on another machine, change
it to that machine's `loganalyser-mcp` or `LogAnalyser.exe --mcp`. To use the agent in every project
with Copilot or Codex, copy it to the tool's user folder (`~/.copilot/agents/`, `~/.codex/agents/`) and
add the server at user level (`copilot mcp`, `codex mcp add`). For Claude Code, follow the steps below.

### Use it in all your Claude Code projects

Do this once per computer, after installing the app. Afterwards, every Claude Code project can analyse
logs, with no files to add to each project.

**On Windows**, open PowerShell and run these two commands:

```powershell
# 1. Connect LogAnalyser to Claude Code for all projects
claude mcp add --scope user loganalyser "--" "$env:LOCALAPPDATA\Programs\LogAnalyser\LogAnalyser.exe" --mcp

# 2. Make the log investigator agent available in all projects
New-Item -ItemType Directory -Force "$HOME\.claude\agents" | Out-Null
Copy-Item "D:\VanguardProjects\Agents\LogAnalyser\.claude\agents\log-investigator.md" "$HOME\.claude\agents\"
```

Type the `--` in quotes, as shown: PowerShell removes a bare `--`, and Claude then stops with
`unknown option '--mcp'`. If you installed LogAnalyser for all users, the app is in
`C:\Program Files\LogAnalyser` instead. In step 2, use the path to your own copy of this repository.

**On a Mac**, open Terminal and run:

```bash
# 1. Connect LogAnalyser to Claude Code for all projects
claude mcp add --scope user loganalyser -- /Applications/LogAnalyser.app/Contents/MacOS/LogAnalyser --mcp

# 2. Make the log investigator agent available in all projects
mkdir -p ~/.claude/agents
cp path/to/loganalyser/.claude/agents/log-investigator.md ~/.claude/agents/
```

If you don't have the repository on the Mac, open `.claude/agents/log-investigator.md` on GitHub,
download the raw file, and save it as `~/.claude/agents/log-investigator.md`.

Keep the server name `loganalyser`: the agent finds its tools under that name.

**Then, in any project:**

1. Start a new Claude Code session and type `/mcp`. **loganalyser** should show as connected.
2. Ask in plain words, for example *"Use the log-investigator agent to find out why the job failed.
   The logs are in C:\logs\app"*, or *"Analyse the logs in ./logs and tell me the likely cause."*
3. Claude runs the analysis and answers with the root cause, the log lines that prove it and what to
   do next. Ask it to open the report if you want the full visual report in the app.

Installing a newer version of the app updates what Claude uses, as the command points to the
installed app. To undo the setup, run `claude mcp remove --scope user loganalyser` and delete
`~/.claude/agents/log-investigator.md`.

**Claude Desktop** can use LogAnalyser too, through its config (see above). **Projects on the claude.ai
website** cannot reach programs on your computer, so LogAnalyser cannot be connected there.

The assistant reads log lines through your AI tool's own model, so they go to that tool's provider.
For logs that must stay on your machine, use the desktop app with Ollama instead.

## What it does

**Reads almost any log.** It works out the format line by line: JSON lines (including numeric
Bunyan/pino levels), log4j/logback, Spring Boot, ASP.NET with Serilog, Python logging, PostgreSQL,
Redis, syslog, and Apache/Nginx access logs. `.gz` files work too. In a folder, it reads files with
log-like names and also text files with no extension or a rotation number, such as `syslog` or
`messages.1`. Stack traces and tracebacks stay attached to the event that started them. When a line
has no level, the level is guessed from its text.

Dates such as `08/06/2026` are read day first or month first, decided per file: a day above 12
settles it, and otherwise the date in the file name (`Web.App.20260608.txt`) or the file's modified
time does. Time zone offsets such as `+01:00` are applied. When an app writes the same event to
several files (an app, a debug and an errors file), it is counted once.

**Finds patterns.** Messages that differ only in numbers, IDs, IPs, UUIDs or durations are grouped
together, so 14,000 lines become a few dozen patterns. URL routes keep their shape:
`/api/orders/{id}/status`. An error's place in your code is part of its pattern, so one message
("Unhandled exception in circuit") thrown from two places counts as two problems.

**Points to the code.** From the stack traces it lists where errors were thrown in your own code
(framework and library frames are skipped): file, line, method, exception, how many times and on
which days. For several days of mixed logs, such as a developer's machine, this list is often a
better guide than the ranking.

**Ranks likely causes.** Every warning and error pattern is grouped by what probably caused it and
scored on the questions an engineer would ask:

- Is it a known failure (about 30 built in: out of memory, full disk, connection pool exhausted,
  DNS, TLS, deadlocks, missing config and more), and is that kind of failure usually a cause or a
  symptom?
- Did it start before the errors spiked, and how many other failures followed it?
- Is it concentrated in the incident, or was it already happening, making it background noise?
- Did it show up in the file (service) that failed first?
- Is it new compared with the healthy run?

Each ranking comes with its reasons in plain language, the first piece of evidence (with the
matched text highlighted), the chain of failures that followed, and steps to try.

**Shows what changed just before.** It lists events that appear for the first time shortly before
the first failure, such as a deploy, a batch job or a config reload. Deploys, restarts and config or
log-level changes are looked for further back, because their effects can take a while to show (a
disk that fills up slowly, for example). With a healthy run, anything that also happened there is
not listed.

**Matches logs.**
- *Across files*: lines that share a request, trace, correlation or order ID are linked into one
  request, with a timeline showing which services it passed through.
- *Across runs*: `--baseline` lists the patterns that are new, missing, or 2x more or less frequent
  than in a healthy run.
- *Against your own patterns*: `--match REGEX` counts and lists matching lines, and the Explorer
  searches with text or regex live.
- *Against your own known issues*: `--rules my-rules.json` adds failure signatures that count as
  causes (see below).

## The report

One self-contained `.html` file, with light and dark themes. Views:

| View | What it answers |
|---|---|
| Likely cause | What broke, why we think so, what followed, what changed just before, what to try |
| Timeline | When it happened: events by level, the incident window, errors by file |
| All causes | Every candidate cause, ranked, with its signals, plus known signatures found |
| Patterns | All message patterns, with frequency over time and healthy-run counts |
| Linked requests | Events that share an ID, followed across files |
| Compare runs | New, missing and changed patterns against the healthy run |
| Explorer | Every line: search (text or regex), filter by level, file, pattern, ID or time, see the surrounding lines, download what is shown |

Click almost anything to open the Explorer filtered to it: a bar on the chart, a pattern, a step
in the failure chain, an ID. In the Explorer, `/` searches, `↑` `↓` move, and `Esc` closes the details.

Times are shown in UTC. Logs without a time zone are read as UTC.

## Options

| Option | |
|---|---|
| `-o, --output FILE` | Report path (default `log-report.html`) |
| `-b, --baseline LOGS...` | Healthy-run logs to compare with |
| `-m, --match REGEX` | Pattern to look for; repeatable |
| `-r, --rules FILE` | Your own known-failure rules (JSON); repeatable |
| `--since`, `--until` | Set the incident window yourself (ISO 8601) instead of detecting it |
| `--json FILE` | Also write the findings as JSON, for scripts or other tools |
| `--max-lines N` | Most events embedded for browsing (default 60,000). The analysis always uses every event; past the limit, the report keeps every warning and error with the lines around it, plus an even sample of the rest. |
| `--open` | Open the report when done |
| `--ai` | Also ask the configured LLM for its reading |
| `--ai-provider`, `--ai-model`, `--ai-url` | Use another provider, model or endpoint than the saved one |
| `--ai-lines N` | Most log lines to send as evidence |
| `--no-redact` | Send lines as written, without hiding personal data |

### Your own rules

```json
[
  {
    "id": "flag_off",
    "title": "Checkout feature flag switched off",
    "category": "Configuration",
    "patterns": ["flag checkout_v2 (?:disabled|off)"],
    "rootness": 0.9,
    "explanation": "Checkout falls back to the legacy path, which cannot handle new carts.",
    "fixes": ["Turn the flag back on in the admin console."]
  }
]
```

`rootness` (0 to 1) says how often this signature is where trouble starts rather than a knock-on
effect. Your rules take priority over the built-in ones.

## Project layout

```
loganalyser/
  parser.py      format detection, timestamps, levels, stack-trace folding, ID extraction
  templates.py   masking and pattern mining
  rules.py       built-in failure signatures, custom rule loading
  analysis.py    incident detection, cause ranking, linking by ID, run comparison
  report.py      writes the HTML report (assets/report.html is the page)
  samples.py     the demo incident
  cli.py         command line
  mcp_server.py  MCP server for Claude, Copilot and other AI tools
  ai/            LLM second opinion: settings, providers, privacy filter, evidence pack
  desktop/       desktop app: window, local server, background jobs, run history, ui/
packaging/       PyInstaller spec, Windows installer, build scripts, icon
.claude/agents/  log-investigator agent for Claude Code (the source of the copies below)
.github/agents/  the same agent for GitHub Copilot
.codex/, .agents/skills/  the same agent and an investigate-logs skill for Codex
scripts/         sync_agents.py writes the Copilot and Codex copies
.mcp.json, .vscode/mcp.json, .codex/config.toml  connect each tool to the MCP server
tests/           pytest
```

Run the tests with `python -m pytest`.
