"""vigilant/ingestion/backends.py — pluggable CPG backend protocol."""
from __future__ import annotations
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

class SemgrepPythonBackend:
    """Wraps Semgrep OSS taint mode for Python files."""
    def supported_extensions(self) -> list[str]:
        return [".py"]
    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import subprocess, json, tempfile, uuid
        target = files[0] if files and len(files) == 1 else str(repo_path)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        subprocess.run(
            ["/home/nishanth/Vigilant-X/.venv/bin/semgrep", "--config=p/python", "--json", "--output", out_path, target],
            capture_output=True, timeout=120,
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
            code_lines = file_contents[fpath][line_start-1:line_end]
            code = "\n".join(code_lines)

            nodes.append({
                "node_id": str(uuid.uuid4()),
                "file_path": fpath,
                "function_name": finding["check_id"].split(".")[-1],
                "line_start": line_start,
                "line_end": line_end,
                "node_type": "CALL_SINK",
                "code": code,
            })
        return {"nodes": nodes, "edges": []}

_EXT_MAP: dict[str, type] = {
    ".cpp": JoernBackend, ".cc": JoernBackend, ".c": JoernBackend,
    ".h": JoernBackend, ".hpp": JoernBackend,
    ".py": SemgrepPythonBackend,
}

def get_backend(ext: str) -> CPGBackend:
    return _EXT_MAP.get(ext, JoernBackend)()
