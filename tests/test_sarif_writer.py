"""Tests for sarif_writer — verifies the confidence gate and negative-finding filter."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import pytest

from vigilant.models import (
    AgentState, PRContext, TaintNode, TaintPath, Vulnerability, VulnerabilityStatus,
)
from vigilant.communication.sarif_writer import write_sarif


def _make_vuln(status: VulnerabilityStatus, confidence: float, z3_proof: str = "") -> Vulnerability:
    node = TaintNode(
        node_id="n1", file_path="foo.cpp", function_name="sink",
        line_number=10, node_role="SINK", label="sink",
    )
    path = TaintPath(
        path_id="p1", source=node, sink=node, crosses_files=False,
    )
    return Vulnerability(
        vuln_id="v1", taint_path=path, status=status,
        confidence=confidence, summary="test finding", z3_proof=z3_proof,
    )


def _make_state(vulns: list[Vulnerability]) -> AgentState:
    ctx = PRContext(repo_path="/tmp", pr_number=1, base_sha="a", head_sha="b")
    return AgentState(pr_context=ctx, vulnerabilities=vulns)


def test_proven_high_confidence_is_written():
    state = _make_state([_make_vuln(VulnerabilityStatus.PROVEN, 0.95)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 1


def test_advisory_is_not_written():
    state = _make_state([_make_vuln(VulnerabilityStatus.ADVISORY, 0.95)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 0


def test_low_confidence_proven_is_not_written():
    state = _make_state([_make_vuln(VulnerabilityStatus.PROVEN, 0.60)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 0


def test_negative_z3_proof_is_not_written():
    state = _make_state([
        _make_vuln(
            VulnerabilityStatus.PROVEN, 0.95,
            z3_proof="No use-after-free detected.",
        )
    ])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 0


def test_sandbox_verified_is_written():
    state = _make_state([_make_vuln(VulnerabilityStatus.SANDBOX_VERIFIED, 0.95)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_warning_is_not_written():
    state = _make_state([_make_vuln(VulnerabilityStatus.WARNING, 0.95)])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = Path(f.name)
    write_sarif(state, out)
    data = json.loads(out.read_text())
    assert len(data["runs"][0]["results"]) == 0
