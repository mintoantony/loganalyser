"""An LLM's reading of the logs, added alongside the built-in analysis.

The built-in engine (analysis.py) always runs first and stays the source of
truth for the report. This package turns its findings plus a sample of the
actual log lines into an evidence pack, sends that to the configured LLM, and
returns a structured second opinion in the same shape as the engine's verdict.
"""

from .advisor import run_ai
from .settings import PROVIDERS, ProviderConfig, Settings

__all__ = ["run_ai", "PROVIDERS", "ProviderConfig", "Settings"]
