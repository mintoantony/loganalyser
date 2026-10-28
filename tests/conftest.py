import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep settings, run history and keys out of the real user profile and keychain."""
    home = tmp_path / "home"
    monkeypatch.setenv("LOGANALYSER_HOME", str(home))
    monkeypatch.setenv("LOGANALYSER_NO_KEYRING", "1")
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY", "AZURE_OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return home
