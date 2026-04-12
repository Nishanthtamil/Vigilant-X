"""Tests that _stable_repo_id returns a consistent value."""
from __future__ import annotations
import tempfile
from pathlib import Path
import subprocess
import pytest

from vigilant.ingestion.cpg_builder import _stable_repo_id


def test_stable_repo_id_consistent_for_same_path():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        id1 = _stable_repo_id(repo)
        id2 = _stable_repo_id(repo)
        assert id1 == id2, "repo_id must be deterministic for the same path"


def test_stable_repo_id_different_for_different_paths():
    with tempfile.TemporaryDirectory() as tmp1:
        with tempfile.TemporaryDirectory() as tmp2:
            id1 = _stable_repo_id(Path(tmp1))
            id2 = _stable_repo_id(Path(tmp2))
            assert id1 != id2, "different repos must have different IDs"


def test_stable_repo_id_is_short_hex():
    with tempfile.TemporaryDirectory() as tmp:
        rid = _stable_repo_id(Path(tmp))
        assert len(rid) <= 64
        assert all(c in "0123456789abcdef" for c in rid), (
            f"repo_id must be a hex string, got: {rid}"
        )
