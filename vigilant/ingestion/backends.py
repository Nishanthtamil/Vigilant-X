"""vigilant/ingestion/backends.py — pluggable CPG backend protocol."""
from __future__ import annotations
import shutil
import json
import tempfile
import uuid
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class CPGBackend(Protocol):
    def build(self, repo_path: Path, files: list[str] | None = None) -> dict: ...
    def supported_extensions(self) -> list[str]: ...


class JoernBackend:
    def supported_extensions(self) -> list[str]:
        return [".cpp", ".cc", ".c", ".h", ".hpp"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        from vigilant.ingestion.cpg_builder import _run_joern
        return _run_joern(repo_path, files)


def _run_semgrep(
    repo_path: Path,
    files: list[str] | None,
    ruleset: str,
) -> dict:
    """Shared Semgrep runner used by Python and JS/TS backends."""
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin is None:
        raise RuntimeError(
            "semgrep not found on PATH. Install it with: pip install semgrep"
        )
    target = files[0] if files and len(files) == 1 else str(repo_path)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name

    import subprocess
    subprocess.run(
        [semgrep_bin, f"--config={ruleset}", "--json", "--output", out_path, target],
        capture_output=True,
        timeout=120,
    )
    try:
        raw = json.loads(Path(out_path).read_text())
    except Exception:
        return {"nodes": [], "edges": []}

    nodes = []
    file_contents: dict[str, list[str]] = {}
    for finding in raw.get("results", []):
        fpath = finding["path"]
        if fpath not in file_contents:
            try:
                file_contents[fpath] = Path(fpath).read_text().splitlines()
            except Exception:
                file_contents[fpath] = []

        line_start = finding["start"]["line"]
        line_end = finding["end"]["line"]
        code_lines = file_contents[fpath][line_start - 1: line_end]
        code = "\n".join(code_lines)

        # Normalize to repo-relative POSIX path
        try:
            rel_path = Path(fpath).relative_to(repo_path).as_posix()
        except ValueError:
            rel_path = fpath

        nodes.append({
            "node_id": str(uuid.uuid4()),
            "file_path": rel_path,
            "function_name": finding["check_id"].split(".")[-1],
            "line_start": line_start,
            "line_end": line_end,
            "node_type": "CALL_SINK",
            "code": code,
        })
    return {"nodes": nodes, "edges": []}


class SemgrepPythonBackend:
    """Semgrep OSS taint mode for Python files."""

    def supported_extensions(self) -> list[str]:
        return [".py"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        return _run_semgrep(repo_path, files, "p/python")


class SemgrepJSBackend:
    """
    Semgrep-based CPG for JavaScript and TypeScript files.

    Uses two rulesets:
    - p/javascript  — covers XSS, prototype pollution, command injection, eval,
                      insecure deserialization, path traversal, SQL injection.
    - p/typescript  — TypeScript-specific type-confusion and null-deref patterns.

    Results from both are merged and deduplicated by (file_path, line_start).
    """

    def supported_extensions(self) -> list[str]:
        return [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        js_results = _run_semgrep(repo_path, files, "p/javascript")
        ts_results = _run_semgrep(repo_path, files, "p/typescript")

        all_nodes = js_results.get("nodes", []) + ts_results.get("nodes", [])

        # Deduplicate by (file_path, line_start, function_name)
        seen: set[tuple[str, int, str]] = set()
        unique_nodes = []
        for node in all_nodes:
            key = (node["file_path"], node["line_start"], node["function_name"])
            if key not in seen:
                seen.add(key)
                unique_nodes.append(node)

        return {"nodes": unique_nodes, "edges": []}


class SemgrepSecurityBackend:
    """
    Generic Semgrep security backend using p/security-audit ruleset.
    Covers Ruby, Go, Java, PHP, and other languages not handled by
    language-specific backends.
    """

    def supported_extensions(self) -> list[str]:
        return [".rb", ".go", ".java", ".php", ".kt"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        return _run_semgrep(repo_path, files, "p/security-audit")


# Extension → backend mapping. More specific backends take priority.
_EXT_MAP: dict[str, type] = {
    # C/C++
    ".cpp": JoernBackend,
    ".cc": JoernBackend,
    ".c": JoernBackend,
    ".h": JoernBackend,
    ".hpp": JoernBackend,
    # Python
    ".py": SemgrepPythonBackend,
    # JavaScript / TypeScript
    ".js": SemgrepJSBackend,
    ".jsx": SemgrepJSBackend,
    ".ts": SemgrepJSBackend,
    ".tsx": SemgrepJSBackend,
    ".mjs": SemgrepJSBackend,
    ".cjs": SemgrepJSBackend,
    # Other languages (best-effort)
    ".rb": SemgrepSecurityBackend,
    ".go": SemgrepSecurityBackend,
    ".java": SemgrepSecurityBackend,
    ".php": SemgrepSecurityBackend,
    ".kt": SemgrepSecurityBackend,
}


def get_backend(ext: str) -> CPGBackend:
    return _EXT_MAP.get(ext, JoernBackend)()
