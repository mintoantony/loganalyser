"""Entry point for the packaged desktop app (PyInstaller starts here)."""

import multiprocessing
import sys

from loganalyser.desktop.app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
