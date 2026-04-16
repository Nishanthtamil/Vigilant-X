"""Tests for vigilant/suppression.py — load_suppressions and apply_suppressions."""
from __future__ import annotations
import tempfile
import uuid
from pathlib import Path
import pytest

from vigilant.suppression import load_suppressions, apply_suppressions
from vigilant.models import (
    Vulnerability, VulnerabilityStatus, TaintNode, TaintPath,
)


def _make_vuln(file_path: str, line: int, rule_id: str) -> Vulnerability:
    node = TaintNode(
        node_id=str(uuid.uuid4()), file_path=file_path,
        function_name="sink", line_number=line,
        node_role="SINK", label="sink",
    )
    path = TaintPath(
        path_id=str(uuid.uuid4()), source=node, sink=node,
        crosses_files=False, rule_id=rule_id,
    )
    return Vulnerability(
        vuln_id=str(uuid.uuid4()), taint_path=path,
        status=VulnerabilityStatus.PROVEN, confidence=0.95,
        summary="test",
    )


def test_exact_suppression_match():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".vigilant-x-ignore").write_text("src/main.cpp:42:no_raw_malloc_free\n")
        sups = load_suppressions(repo)
        vulns = [_make_vuln("src/main.cpp", 42, "no_raw_malloc_free")]
        result = apply_suppressions(vulns, sups)
        assert result == []


def test_wildcard_line_zero_suppression():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".vigilant-x-ignore").write_text("src/main.cpp:0:no_raw_malloc_free\n")
        sups = load_suppressions(repo)
        vulns = [
            _make_vuln("src/main.cpp", 10, "no_raw_malloc_free"),
            _make_vuln("src/main.cpp", 99, "no_raw_malloc_free"),
        ]
        result = apply_suppressions(vulns, sups)
        assert result == []


def test_different_rule_not_suppressed():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".vigilant-x-ignore").write_text("src/main.cpp:42:no_raw_malloc_free\n")
        sups = load_suppressions(repo)
        vulns = [_make_vuln("src/main.cpp", 42, "no_strcpy_strcat")]
        result = apply_suppressions(vulns, sups)
        assert len(result) == 1


def test_malformed_lines_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".vigilant-x-ignore").write_text(
            "# comment\n"
            "malformed-no-colons\n"
            "src/main.cpp:42:no_raw_malloc_free\n"
        )
        sups = load_suppressions(repo)
        assert len(sups) == 1


def test_missing_ignore_file_returns_empty():
    with tempfile.TemporaryDirectory() as tmp:
        sups = load_suppressions(Path(tmp))
        assert sups == set()


def test_unsuppressed_vulns_pass_through():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".vigilant-x-ignore").write_text("other/file.cpp:10:some_rule\n")
        sups = load_suppressions(repo)
        vulns = [_make_vuln("src/main.cpp", 42, "no_raw_malloc_free")]
        result = apply_suppressions(vulns, sups)
        assert len(result) == 1


def test_empty_vulns_list():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".vigilant-x-ignore").write_text("src/main.cpp:42:rule\n")
        sups = load_suppressions(repo)
        assert apply_suppressions([], sups) == []
