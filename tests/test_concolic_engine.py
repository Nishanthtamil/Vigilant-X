"""
tests/test_concolic_engine.py
──────────────────────────────
Unit tests for the Z3 solver and HeuristicPathPruner components.
No external services required.
"""

import uuid
import pytest

from vigilant.analysis.concolic_engine import (
    ConcolicEngine,
    HeuristicPathPruner,
    Z3Solver,
    Z3UnknownError,
)
from vigilant.models import TaintNode, TaintPath, VulnerabilityStatus


def _make_path(
    src_func="get_user_input",
    snk_func="memcpy",
    src_file="input.cpp",
    snk_file="buffer.cpp",
    crosses_files=True,
    severity="CRITICAL",
) -> TaintPath:
    return TaintPath(
        path_id=str(uuid.uuid4()),
        source=TaintNode(
            node_id=str(uuid.uuid4()),
            file_path=src_file,
            function_name=src_func,
            line_number=10,
            node_role="SOURCE",
            label=src_func,
        ),
        sink=TaintNode(
            node_id=str(uuid.uuid4()),
            file_path=snk_file,
            function_name=snk_func,
            line_number=42,
            node_role="SINK",
            label=snk_func,
        ),
        crosses_files=crosses_files,
        rule_severity=severity,
    )


# ── Z3 Solver ────────────────────────────────────────────────────────────────


class TestZ3Solver:
    def test_memcpy_path_returns_proven(self, mocker):
        mock_builder = mocker.Mock()
        mock_builder.get_node.return_value = {}
        solver = Z3Solver(builder=mock_builder)  # No LLM provided, should use fallback
        path = _make_path(snk_func="memcpy")
        status, witnesses, formula = solver.solve(path)
        assert status == VulnerabilityStatus.PROVEN
        # Fallback uses basic reachability
        assert formula == "sink_is_reachable"

    def test_free_path_returns_proven(self, mocker):
        mock_builder = mocker.Mock()
        mock_builder.get_node.return_value = {}
        solver = Z3Solver(builder=mock_builder)
        path = _make_path(snk_func="free")
        status, witnesses, formula = solver.solve(path)
        assert status == VulnerabilityStatus.PROVEN
        assert formula == "sink_is_reachable"

    def test_formula_is_populated(self, mocker):
        mock_builder = mocker.Mock()
        mock_builder.get_node.return_value = {}
        solver = Z3Solver(builder=mock_builder)
        path = _make_path(snk_func="strcpy")
        status, witnesses, formula = solver.solve(path)
        assert formula == "sink_is_reachable"

    def test_z3_solver_init(self, mocker):
        """Z3Solver should be constructable without error."""
        mock_builder = mocker.Mock()
        solver = Z3Solver(builder=mock_builder)
        assert solver is not None


# ── HeuristicPathPruner ───────────────────────────────────────────────────────


class TestHeuristicPathPruner:
    def test_cross_file_scored_higher(self):
        pruner = HeuristicPathPruner(llm=None)
        local_path = _make_path(crosses_files=False, snk_func="printf")
        cross_path = _make_path(crosses_files=True, snk_func="printf")
        assert pruner._score(cross_path) > pruner._score(local_path)

    def test_high_priority_sink_scored_higher(self):
        pruner = HeuristicPathPruner(llm=None)
        low = _make_path(snk_func="printf", crosses_files=False)
        high = _make_path(snk_func="memcpy", crosses_files=False)
        assert pruner._score(high) > pruner._score(low)

    def test_prune_caps_at_max(self):
        pruner = HeuristicPathPruner(llm=None)
        paths = [_make_path() for _ in range(50)]
        pruned = pruner.prune(paths)
        assert len(pruned) <= pruner.MAX_PATHS_BEFORE_LLM

    def test_prune_empty(self):
        pruner = HeuristicPathPruner(llm=None)
        assert pruner.prune([]) == []


# ── ConcolicEngine ────────────────────────────────────────────────────────────


class TestConcolicEngine:
    def test_advisory_paths_skip_z3(self, mocker):
        engine = ConcolicEngine.__new__(ConcolicEngine)
        engine.llm = None
        engine.builder = mocker.Mock()
        engine.pruner = HeuristicPathPruner(llm=None)
        engine.z3_solver = Z3Solver(builder=engine.builder)
        engine.fuzzer = None  # type: ignore[assignment]

        advisory = _make_path(severity="ADVISORY")
        vulns = engine.analyze([advisory])
        assert len(vulns) == 1
        assert vulns[0].status == VulnerabilityStatus.ADVISORY

    def test_critical_memcpy_proven(self, mocker):
        engine = ConcolicEngine.__new__(ConcolicEngine)
        engine.llm = None
        engine.builder = mocker.Mock()
        # Mock get_node to return dummy hashes
        engine.builder.get_node.return_value = {"content_hash": "dummy"}
        engine.builder.driver.session.side_effect = Exception("Neo4j down")
        
        engine.pruner = HeuristicPathPruner(llm=None)
        engine.z3_solver = Z3Solver(builder=engine.builder)
        engine.fuzzer = None  # type: ignore[assignment]

        critical = _make_path(snk_func="memcpy", severity="CRITICAL")
        vulns = engine.analyze([critical])
        assert len(vulns) == 1
        assert vulns[0].status in {VulnerabilityStatus.PROVEN, VulnerabilityStatus.WARNING}
