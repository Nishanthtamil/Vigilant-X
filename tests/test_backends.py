"""Tests for the backend registry and JS/TS backend registration."""
from vigilant.ingestion.backends import (
    get_backend, SemgrepJSBackend, BanditBackend, JoernBackend,
    GosecBackend, SpotBugsBackend, BrakemanBackend, RustBackend,
)


def test_cpp_uses_joern():
    assert isinstance(get_backend(".cpp"), JoernBackend)
    assert isinstance(get_backend(".h"), JoernBackend)


def test_python_uses_bandit():
    assert isinstance(get_backend(".py"), BanditBackend)


def test_js_uses_semgrep_js():
    assert isinstance(get_backend(".js"), SemgrepJSBackend)
    assert isinstance(get_backend(".ts"), SemgrepJSBackend)
    assert isinstance(get_backend(".tsx"), SemgrepJSBackend)
    assert isinstance(get_backend(".jsx"), SemgrepJSBackend)
    assert isinstance(get_backend(".mjs"), SemgrepJSBackend)


def test_go_uses_gosec():
    assert isinstance(get_backend(".go"), GosecBackend)


def test_java_uses_spotbugs():
    assert isinstance(get_backend(".java"), SpotBugsBackend)


def test_ruby_uses_brakeman():
    assert isinstance(get_backend(".rb"), BrakemanBackend)


def test_rust_uses_rust_backend():
    assert isinstance(get_backend(".rs"), RustBackend)


def test_unknown_extension_falls_back_to_joern():
    assert isinstance(get_backend(".xyz"), JoernBackend)
