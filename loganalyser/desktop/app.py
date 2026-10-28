"""Start the desktop app: a native window (pywebview) showing the local app server.

Run with ``python -m loganalyser.desktop``. If no native web view is available
(or with ``--browser``), the same app opens in the default browser instead.
"""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from urllib.parse import quote

from ..ai import Settings
from .server import App, Dialogs


class WindowDialogs(Dialogs):
    """Native open/save dialogs through pywebview."""

    available = True

    def __init__(self, webview_module):
        self.webview = webview_module
        self.window = None
        fd = getattr(webview_module, "FileDialog", None)
        self.FOLDER = fd.FOLDER if fd else webview_module.FOLDER_DIALOG
        self.OPEN = fd.OPEN if fd else webview_module.OPEN_DIALOG
        self.SAVE = fd.SAVE if fd else webview_module.SAVE_DIALOG

    def pick_folder(self) -> list[str]:
        return list(self.window.create_file_dialog(self.FOLDER) or [])

    def pick_files(self) -> list[str]:
        types = ("Log files (*.log;*.txt;*.json;*.jsonl;*.ndjson;*.gz;*.out;*.err)", "All files (*.*)")
        return list(self.window.create_file_dialog(self.OPEN, allow_multiple=True, file_types=types) or [])

    def save_file(self, suggested: str) -> str | None:
        result = self.window.create_file_dialog(self.SAVE, save_filename=suggested,
                                                file_types=("HTML report (*.html)",))
        if not result:
            return None
        return result if isinstance(result, str) else result[0]


def _enable_drop_paths(window) -> None:
    """Ask pywebview to expose full paths of dropped files (File.pywebviewFullPath) to the page."""
    try:
        from webview.dom import DOMEventHandler

        window.dom.document.events.drop += DOMEventHandler(lambda event: None, True, True)
    except Exception:  # noqa: BLE001 - without it, dropped files are uploaded instead
        pass


def run_in_browser(app: App, run_id: str | None = None) -> int:
    app.serve_in_background()
    print(f"LogAnalyser is running at {app.url}\nKeep this window open; press Ctrl+C to stop.", file=sys.stderr)
    webbrowser.open(_start_url(app, run_id))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        app.close()
    return 0


def smoke_test() -> int:
    """Check a build without opening anything: assets present, libraries load, the server answers."""
    import json
    import urllib.request
    from pathlib import Path

    from .. import report
    from .server import UI

    checks = {"ui": (UI / "index.html").is_file(), "report_template": Path(report._TEMPLATE).is_file()}
    for module in ("webview", "anthropic", "keyring", "mcp.server.mcpserver"):
        try:
            __import__(module)
            checks[module] = True
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            checks[module] = f"missing: {exc}"
    app = App()
    app.serve_in_background()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{app.port}/api/state", headers={"X-Token": app.token})
        with urllib.request.urlopen(req, timeout=10) as res:
            checks["server"] = json.loads(res.read())["version"]
    finally:
        app.close()
    print(json.dumps(checks, indent=2))
    return 0 if all(v is True or isinstance(v, str) and not v.startswith("missing") for v in checks.values()) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="loganalyser-app", description="LogAnalyser desktop app")
    parser.add_argument("--browser", action="store_true", help="Open in the default browser instead of a window")
    parser.add_argument("--debug", action="store_true", help="Enable the web inspector")
    parser.add_argument("--smoke-test", action="store_true", help="Check the installation and exit")
    parser.add_argument("--run", metavar="ID", help="Open this saved analysis")
    parser.add_argument("--mcp", action="store_true", help="Run as an MCP server (stdio) for AI tools instead")
    args = parser.parse_args(argv)

    if args.mcp:
        from ..mcp_server import main as serve_mcp
        return serve_mcp()
    if args.smoke_test:
        return smoke_test()
    if args.browser:
        return run_in_browser(App(), args.run)
    try:
        import webview
    except ImportError:
        print("pywebview is not installed, so the app opens in your browser.", file=sys.stderr)
        return run_in_browser(App(), args.run)

    dialogs = WindowDialogs(webview)
    app = App(dialogs)
    app.serve_in_background()
    window = webview.create_window("LogAnalyser", _start_url(app, args.run), width=1380, height=900, min_size=(980, 640),
                                   background_color="#0e161f", text_select=True)
    dialogs.window = window
    storage = Settings.folder() / "webview"
    storage.mkdir(parents=True, exist_ok=True)
    try:
        webview.start(_enable_drop_paths, window, debug=args.debug, private_mode=False, storage_path=str(storage))
    except Exception as exc:  # noqa: BLE001 - e.g. no WebView2 runtime on an old Windows install
        print(f"Could not open a native window ({exc}); opening in your browser instead.", file=sys.stderr)
        app.close()
        return run_in_browser(App(), args.run)
    app.close()
    return 0


def _start_url(app: App, run_id: str | None) -> str:
    """The app's address, opening a saved analysis straight away when one is given."""
    return f"{app.url}#run={quote(run_id)}" if run_id else app.url
