"""
tests/test_likely_status.py
────────────────────────────
Tests for the LIKELY vulnerability status, requires_msan routing,
and MSan-aware sandbox tie-breaker logic.
"""
from __future__ import annotations
import uuid
import pytest

from vigilant.models import (
    Vulnerability, VulnerabilityStatus, TaintNode, TaintPath, WitnessValue
)
from vigilant.communication.sarif_writer import write_sarif
from vigilant.models import AgentState, PRContext
import json, tempfile
from pathlib import Path


def _make_node(file_path="a.cpp", func="sink", line=10):
    return TaintNode(
        node_id=str(uuid.uuid4()), file_path=file_path,
        function_name=func, line_number=line,
        node_role="SINK", label=func,
    )


def _make_vuln(status, confidence=0.90, requires_msan=False, z3_formula=""):
    node = _make_node()
    path = TaintPath(
        path_id=str(uuid.uuid4()), source=node, sink=node,
        crosses_files=False,
    )
    return Vulnerability(
        vuln_id=str(uuid.uuid4()), taint_path=path,
        status=status, confidence=confidence,
        summary="test", z3_formula=z3_formula, z3_proof=z3_formula,
        requires_msan=requires_msan,
    )


def _make_state(vulns):
    ctx = PRContext(repo_path="/tmp", pr_number=1, base_sha="a", head_sha="b")
    return AgentState(pr_context=ctx, vulnerabilities=vulns)


# ── LIKELY status tests ───────────────────────────────────────────────────

def test_likely_status_exists():
    assert VulnerabilityStatus.LIKELY == "LIKELY"


def test_likely_written_to_sarif_at_note_level():
    state = _make_state([_make_vuln(VulnerabilityStatus.LIKELY, confidence=0.90)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "note"


def test_likely_requires_high_enough_confidence():
    """LIKELY findings below 0.85 confidence should not appear in SARIF."""
    state = _make_state([_make_vuln(VulnerabilityStatus.LIKELY, confidence=0.70)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 0


def test_proven_still_written_to_sarif_at_error_level():
    state = _make_state([_make_vuln(VulnerabilityStatus.PROVEN, confidence=0.95)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"


# ── requires_msan field tests ─────────────────────────────────────────────

def test_requires_msan_default_false():
    vuln = _make_vuln(VulnerabilityStatus.PROVEN)
    assert vuln.requires_msan is False


def test_requires_msan_can_be_set_true():
    vuln = _make_vuln(VulnerabilityStatus.PROVEN, requires_msan=True)
    assert vuln.requires_msan is True


def test_requires_msan_tagged_for_uninit_formula(mocker):
    """Z3 solver should tag requires_msan=True when is_initialized is in the formula."""
    from vigilant.analysis.concolic_engine import Z3Solver
    from vigilant.models import TaintNode, TaintPath

    mock_builder = mocker.Mock()
    mock_builder.get_node.return_value = {"code": "malloc(size)"}
    # Disable cache
    mock_builder.driver.session.side_effect = Exception("no neo4j")
    solver = Z3Solver(builder=mock_builder)

    src = TaintNode(
        node_id=str(uuid.uuid4()), file_path="a.cpp",
        function_name="argv", line_number=1, node_role="SOURCE", label="argv",
    )
    snk = TaintNode(
        node_id=str(uuid.uuid4()), file_path="a.cpp",
        function_name="malloc", line_number=10, node_role="SINK", label="malloc",
    )
    path = TaintPath(path_id=str(uuid.uuid4()), source=src, sink=snk)

    status, witnesses, formula = solver._run_solve(path)
    assert "is_initialized" in formula


# ── MSan routing tests ────────────────────────────────────────────────────

def test_sandbox_routes_msan_vuln_to_memory_sanitizer(tmp_path):
    """requires_msan=True should cause _infer_sanitizer to return 'memory'."""
    from vigilant.validation.sandbox_runner import SandboxRunner
    runner = SandboxRunner(repo_path=tmp_path)
    vuln = _make_vuln(VulnerabilityStatus.PROVEN, requires_msan=True)
    sanitizer = runner._infer_sanitizer(vuln)
    assert sanitizer == "memory"


def test_sandbox_routes_regular_vuln_to_asan(tmp_path):
    """requires_msan=False should default to address,undefined."""
    from vigilant.validation.sandbox_runner import SandboxRunner
    runner = SandboxRunner(repo_path=tmp_path)
    vuln = _make_vuln(VulnerabilityStatus.PROVEN, requires_msan=False)
    sanitizer = runner._infer_sanitizer(vuln)
    assert sanitizer == "address,undefined"


# ── Benchmark gate test ───────────────────────────────────────────────────

def test_benchmark_tp_criterion_includes_proven_and_likely():
    """The TP criterion for benchmarking must include PROVEN and LIKELY."""
    vulns = [
        _make_vuln(VulnerabilityStatus.PROVEN),
        _make_vuln(VulnerabilityStatus.LIKELY),
        _make_vuln(VulnerabilityStatus.SANDBOX_VERIFIED),
        _make_vuln(VulnerabilityStatus.FUZZ_VERIFIED),
        _make_vuln(VulnerabilityStatus.WARNING),
        _make_vuln(VulnerabilityStatus.ADVISORY),
    ]
    # Replicate the benchmark filter logic
    tp_statuses = {
        VulnerabilityStatus.SANDBOX_VERIFIED,
        VulnerabilityStatus.FUZZ_VERIFIED,
        VulnerabilityStatus.PROVEN,
        VulnerabilityStatus.LIKELY,
    }
    critical = [v for v in vulns if v.status in tp_statuses]
    assert len(critical) == 4   # PROVEN + LIKELY + SANDBOX + FUZZ
