"""Tests for Z3Solver._encode_path — verifies each sink category returns SAT."""
from __future__ import annotations
import uuid
import pytest
import z3

from vigilant.models import TaintNode, TaintPath, VulnerabilityStatus


def _make_path(sink_name: str, sink_code: str = "") -> TaintPath:
    src = TaintNode(
        node_id=str(uuid.uuid4()), file_path="a.cpp",
        function_name="source", line_number=1, node_role="SOURCE", label="src",
    )
    snk = TaintNode(
        node_id=str(uuid.uuid4()), file_path="a.cpp",
        function_name=sink_name, line_number=10, node_role="SINK", label=sink_name,
    )
    return TaintPath(path_id=str(uuid.uuid4()), source=src, sink=snk)


class MockBuilder:
    """Minimal stub replacing CPGBuilder for unit tests."""
    def __init__(self, sink_code: str = ""):
        self._sink_code = sink_code

    def get_node(self, node_id: str):
        return {"code": self._sink_code}

    @property
    def driver(self):
        class _FakeSession:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def run(self, *a, **kw): return iter([])
        class _FakeDriver:
            def session(self): return _FakeSession()
        return _FakeDriver()


@pytest.fixture
def solver():
    from vigilant.analysis.concolic_engine import Z3Solver
    return Z3Solver(llm=None, builder=MockBuilder())


def test_memcpy_overflow_sat(solver):
    path = _make_path("memcpy")
    solver.builder = MockBuilder(sink_code="memcpy(buf, src, 1024)")
    status, witnesses, formula = solver._run_solve(path)
    assert status == VulnerabilityStatus.PROVEN
    assert "input_len" in formula or "dest_size" in formula


def test_strcpy_overflow_sat(solver):
    path = _make_path("strcpy")
    solver.builder = MockBuilder(sink_code='strcpy(buf[64], input)')
    status, witnesses, formula = solver._run_solve(path)
    assert status == VulnerabilityStatus.PROVEN


def test_free_uaf_sat(solver):
    path = _make_path("free")
    solver.builder = MockBuilder(sink_code="free(ptr)")
    status, witnesses, formula = solver._run_solve(path)
    assert status == VulnerabilityStatus.PROVEN
    assert "is_freed" in formula


def test_system_injection_sat(solver):
    path = _make_path("system")
    solver.builder = MockBuilder(sink_code="system(cmd)")
    status, witnesses, formula = solver._run_solve(path)
    assert status == VulnerabilityStatus.PROVEN
    assert "has_metachar" in formula


def test_malloc_uninit_sat(solver):
    path = _make_path("malloc")
    solver.builder = MockBuilder(sink_code="malloc(size)")
    status, witnesses, formula = solver._run_solve(path)
    assert status == VulnerabilityStatus.PROVEN
    assert "is_initialized" in formula


def test_calloc_overflow_sat(solver):
    path = _make_path("calloc")
    solver.builder = MockBuilder(sink_code="calloc(count, sizeof(T))")
    status, witnesses, formula = solver._run_solve(path)
    assert status == VulnerabilityStatus.PROVEN
    assert "overflow" in formula.lower() or "count" in formula
