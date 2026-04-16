"""
tests/test_taint_tracker.py
────────────────────────────
Unit tests for TaintTracker using a mocked Neo4j driver.
No real database connection required.
"""

import uuid
import pytest
from unittest.mock import MagicMock, patch

from vigilant.analysis.taint_tracker import TaintTracker
from vigilant.config import CodeLaw
from vigilant.models import TaintPath


def _make_mock_record(
    src_func="argv",
    snk_func="memcpy",
    src_file="main.cpp",
    snk_file="utils.cpp",
    num_intermediates=1,
) -> dict:
    intermediates = [
        {
            "node_id": str(uuid.uuid4()),
            "file_path": "middle.cpp",
            "function_name": f"intermediate_{i}",
            "line_number": 20 + i,
        }
        for i in range(num_intermediates)
    ]
    path_nodes = (
        [{"node_id": str(uuid.uuid4()), "file_path": src_file, "function_name": src_func, "line_number": 5}]
        + intermediates
        + [{"node_id": str(uuid.uuid4()), "file_path": snk_file, "function_name": snk_func, "line_number": 99}]
    )
    return {
        "src_id": str(uuid.uuid4()),
        "src_file": src_file,
        "src_func": src_func,
        "src_line": 5,
        "snk_id": str(uuid.uuid4()),
        "snk_file": snk_file,
        "snk_func": snk_func,
        "snk_line": 99,
        "path_nodes": path_nodes,
        "path_len": len(path_nodes),
    }


class TestTaintTracker:
    def _make_tracker_with_mock(self, records: list[dict]) -> TaintTracker:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__.return_value = mock_session

        # APOC check — return None (not available) so fallback Cypher is used
        mock_session.run.side_effect = lambda q, **kwargs: (
            MagicMock(single=lambda: None)  # APOC version check fails
            if "apoc.version" in q
            else MagicMock(
                __iter__=lambda self: iter([MagicMock(data=lambda: r) for r in records])
            )
        )
        tracker = TaintTracker.__new__(TaintTracker)
        tracker.driver = mock_driver
        tracker.code_law = CodeLaw.__new__(CodeLaw)
        tracker.code_law.rules = []
        tracker._apoc_available = False
        tracker._framework_detector = None
        return tracker

    def test_returns_taint_paths(self):
        records = [_make_mock_record()]
        tracker = self._make_tracker_with_mock(records)
        paths = tracker.find_taint_paths()
        assert len(paths) == 1
        assert isinstance(paths[0], TaintPath)

    def test_cross_file_detected(self):
        record = _make_mock_record(src_file="main.cpp", snk_file="utils.cpp")
        tracker = self._make_tracker_with_mock([record])
        paths = tracker.find_taint_paths()
        assert paths[0].crosses_files is True

    def test_same_file_not_cross_file(self):
        record = _make_mock_record(src_file="main.cpp", snk_file="main.cpp")
        tracker = self._make_tracker_with_mock([record])
        paths = tracker.find_taint_paths()
        assert paths[0].crosses_files is False

    def test_source_and_sink_nodes_populated(self):
        records = [_make_mock_record(src_func="argv", snk_func="memcpy")]
        tracker = self._make_tracker_with_mock(records)
        paths = tracker.find_taint_paths()
        assert paths[0].source.function_name == "argv"
        assert paths[0].sink.function_name == "memcpy"

    def test_intermediates_populated(self):
        records = [_make_mock_record(num_intermediates=2)]
        tracker = self._make_tracker_with_mock(records)
        paths = tracker.find_taint_paths()
        assert len(paths[0].intermediate_nodes) == 2

    def test_empty_result_returns_empty_list(self):
        tracker = self._make_tracker_with_mock([])
        paths = tracker.find_taint_paths()
        assert paths == []
