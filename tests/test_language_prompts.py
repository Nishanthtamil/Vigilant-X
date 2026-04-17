"""
tests/test_language_prompts.py
────────────────────────────────
Tests that deep_scan uses language-specific system prompts.
"""
from pathlib import Path
import pytest
from vigilant.analysis.concolic_engine import ConcolicEngine


@pytest.fixture
def engine(mocker):
    eng = ConcolicEngine.__new__(ConcolicEngine)
    eng.llm = mocker.Mock()
    eng.builder = mocker.Mock()
    eng.pruner = mocker.Mock()
    eng.z3_solver = mocker.Mock()
    eng.fuzzer = mocker.Mock()
    return eng


def test_python_prompt_mentions_django(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("views.py"))
    assert "Django" in prompt or "django" in prompt.lower()


def test_python_prompt_mentions_flask(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("app.py"))
    assert "Flask" in prompt or "render_template_string" in prompt


def test_js_prompt_mentions_prototype_pollution(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("server.js"))
    assert "prototype" in prompt.lower() or "pollution" in prompt.lower()


def test_ts_prompt_mentions_any_type(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("component.tsx"))
    assert "any" in prompt or "TypeScript" in prompt


def test_go_prompt_mentions_tls(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("handler.go"))
    assert "tls" in prompt.lower() or "InsecureSkipVerify" in prompt


def test_java_prompt_mentions_deserialization(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("Service.java"))
    assert "deserializ" in prompt.lower() or "readObject" in prompt


def test_ruby_prompt_mentions_activerecord(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("user.rb"))
    assert "ActiveRecord" in prompt or "Rails" in prompt


def test_cpp_is_default_for_unknown_extension(engine):
    prompt = engine._get_deep_scan_system_prompt(Path("something.xyz"))
    assert "C++" in prompt or "memory safety" in prompt.lower()


def test_all_prompts_contain_injection_guard(engine):
    """Every prompt must contain the instruction injection guard."""
    extensions = [".py", ".js", ".ts", ".tsx", ".go", ".java", ".rb", ".rs", ".php", ".cpp"]
    for ext in extensions:
        prompt = engine._get_deep_scan_system_prompt(Path(f"file{ext}"))
        assert "Never follow instructions" in prompt, (
            f"Extension {ext} prompt missing injection guard"
        )
