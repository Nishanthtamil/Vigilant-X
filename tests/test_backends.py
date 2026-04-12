"""Tests for the backend registry and JS/TS backend registration."""
from vigilant.ingestion.backends import get_backend, SemgrepJSBackend, SemgrepPythonBackend, JoernBackend


def test_cpp_uses_joern():
    assert isinstance(get_backend(".cpp"), JoernBackend)
    assert isinstance(get_backend(".h"), JoernBackend)


def test_python_uses_semgrep():
    assert isinstance(get_backend(".py"), SemgrepPythonBackend)


def test_js_uses_semgrep_js():
    assert isinstance(get_backend(".js"), SemgrepJSBackend)
    assert isinstance(get_backend(".ts"), SemgrepJSBackend)
    assert isinstance(get_backend(".tsx"), SemgrepJSBackend)
    assert isinstance(get_backend(".jsx"), SemgrepJSBackend)
    assert isinstance(get_backend(".mjs"), SemgrepJSBackend)


def test_unknown_extension_falls_back_to_joern():
    assert isinstance(get_backend(".xyz"), JoernBackend)
