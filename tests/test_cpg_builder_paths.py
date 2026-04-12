"""Tests that _stub_cpg emits repo-relative POSIX paths."""
from __future__ import annotations
import tempfile
from pathlib import Path
import pytest

from vigilant.ingestion.cpg_builder import _stub_cpg


def test_stub_cpg_emits_relative_paths():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        src = repo / "src" / "main.cpp"
        src.parent.mkdir()
        src.write_text("""
#include <cstring>
void foo(const char* in) {
    char buf[64];
    strcpy(buf, in);
}
int main(int argc, char* argv[]) {
    foo(argv[1]);
    return 0;
}
""")
        result = _stub_cpg(repo, None)
        nodes = result["nodes"]
        assert len(nodes) > 0, "stub CPG produced no nodes"
        for node in nodes:
            fp = node["file_path"]
            assert not Path(fp).is_absolute(), (
                f"file_path must be repo-relative, got absolute: {fp}"
            )
            assert "\\" not in fp, (
                f"file_path must use POSIX separators, got: {fp}"
            )


def test_stub_cpg_sink_and_source_same_relative_form():
    """Source and sink file_path values must be in the same form so dedup works."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        src = repo / "vuln.cpp"
        src.write_text("""
#include <cstdlib>
void bad(const char* in) {
    char* p = (char*)malloc(32);
    free(p);
    int x = p[0];
}
""")
        result = _stub_cpg(repo, None)
        file_paths = {n["file_path"] for n in result["nodes"]}
        # All paths must be non-absolute
        for fp in file_paths:
            assert not Path(fp).is_absolute(), f"absolute path leaked: {fp}"
