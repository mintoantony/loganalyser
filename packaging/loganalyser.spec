# PyInstaller build for the LogAnalyser desktop app.
# Build from the repository root:  pyinstaller packaging/loganalyser.spec --noconfirm
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
PKG = ROOT / "loganalyser"
APP_NAME = "LogAnalyser"
VERSION = "1.1.0"

datas = [
    (str(PKG / "assets"), "loganalyser/assets"),
    (str(PKG / "desktop" / "ui"), "loganalyser/desktop/ui"),
]
datas += collect_data_files("webview")
datas += collect_data_files("anthropic")
datas += copy_metadata("mcp")  # the MCP server (--mcp) reads its own version

hiddenimports = (
    collect_submodules("keyring.backends")
    + collect_submodules("webview.platforms")
    + collect_submodules("mcp.server.mcpserver")
    + ["loganalyser.desktop.app", "loganalyser.ai.providers", "loganalyser.mcp_server"]
)

a = Analysis(
    [str(ROOT / "packaging" / "launch.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)

icon = str(ROOT / "packaging" / ("icon.icns" if sys.platform == "darwin" else "icon.ico"))
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    console=False,
    icon=icon,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name=APP_NAME, upx=False)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name=f"{APP_NAME}.app",
        icon=icon,
        bundle_identifier="com.loganalyser.desktop",
        version=VERSION,
        info_plist={
            "CFBundleShortVersionString": VERSION,
            "CFBundleDisplayName": APP_NAME,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
