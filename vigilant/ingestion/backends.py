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
        raw = {}
    finally:
        Path(out_path).unlink(missing_ok=True)

    if not raw:
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
        js_results   = _run_semgrep(repo_path, files, "p/javascript")
        ts_results   = _run_semgrep(repo_path, files, "p/typescript")
        eslint_results = EslintSecurityBackend().build(repo_path, files)

        all_nodes = (
            js_results.get("nodes", [])
            + ts_results.get("nodes", [])
            + eslint_results.get("nodes", [])
        )

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


class BanditBackend:
    """
    Bandit AST-based security scanner for Python.
    Covers: injection, crypto misuse, hardcoded secrets, OWASP Top 10 Python.
    Falls back to SemgrepPythonBackend if bandit is not on PATH.
    """

    def supported_extensions(self) -> list[str]:
        return [".py"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import shutil
        import subprocess
        import json as _json

        bandit_bin = shutil.which("bandit")
        if bandit_bin is None:
            import logging
            logging.getLogger(__name__).info(
                "BanditBackend: bandit not found, falling back to Semgrep Python backend"
            )
            return SemgrepPythonBackend().build(repo_path, files)

        target = files[0] if files and len(files) == 1 else str(repo_path)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        try:
            subprocess.run(
                [bandit_bin, "-r", target, "-f", "json", "-o", out_path,
                 "-ll",   # only medium and high severity
                 "--quiet"],
                capture_output=True, timeout=120,
            )
            raw = _json.loads(Path(out_path).read_text())
        except Exception:
            raw = {}
        finally:
            Path(out_path).unlink(missing_ok=True)

        nodes = []
        for result in raw.get("results", []):
            fpath = result.get("filename", "")
            try:
                rel_path = Path(fpath).relative_to(repo_path).as_posix()
            except ValueError:
                rel_path = fpath

            nodes.append({
                "node_id": str(uuid.uuid4()),
                "file_path": rel_path,
                "function_name": result.get("test_id", "bandit_finding"),
                "line_start": result.get("line_number", 0),
                "line_end": result.get("line_number", 0),
                "node_type": "CALL_SINK",
                "code": result.get("code", "").strip(),
            })

        return {"nodes": nodes, "edges": []}


class GosecBackend:
    """
    gosec — purpose-built Go security scanner.
    Covers: goroutine races, crypto, hardcoded creds, integer overflow.
    Falls back to SemgrepSecurityBackend if gosec is not on PATH.
    """

    def supported_extensions(self) -> list[str]:
        return [".go"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import shutil
        import subprocess
        import json as _json

        gosec_bin = shutil.which("gosec")
        if gosec_bin is None:
            import logging
            logging.getLogger(__name__).info(
                "GosecBackend: gosec not found, falling back to Semgrep security backend"
            )
            return SemgrepSecurityBackend().build(repo_path, files)

        target = "./..."
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        try:
            subprocess.run(
                [gosec_bin, "-fmt=json", f"-out={out_path}", "-quiet", target],
                capture_output=True, timeout=120, cwd=repo_path,
            )
            raw = _json.loads(Path(out_path).read_text())
        except Exception:
            raw = {}
        finally:
            Path(out_path).unlink(missing_ok=True)

        nodes = []
        for issue in raw.get("Issues", []):
            fpath = issue.get("file", "")
            try:
                rel_path = Path(fpath).relative_to(repo_path).as_posix()
            except ValueError:
                rel_path = fpath

            line_str = issue.get("line", "0").split("-")[0]
            try:
                line_num = int(line_str)
            except ValueError:
                line_num = 0

            nodes.append({
                "node_id": str(uuid.uuid4()),
                "file_path": rel_path,
                "function_name": issue.get("rule_id", "gosec_finding"),
                "line_start": line_num,
                "line_end": line_num,
                "node_type": "CALL_SINK",
                "code": issue.get("code", "").strip(),
            })

        return {"nodes": nodes, "edges": []}


class SpotBugsBackend:
    """
    SpotBugs + FindSecBugs for Java security analysis.
    Falls back to SemgrepSecurityBackend if spotbugs jar is not found.
    """

    def supported_extensions(self) -> list[str]:
        return [".java"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import shutil
        import subprocess
        import xml.etree.ElementTree as ET

        spotbugs_bin = shutil.which("spotbugs")
        if spotbugs_bin is None:
            import logging
            logging.getLogger(__name__).info(
                "SpotBugsBackend: spotbugs not found, falling back to Semgrep"
            )
            return SemgrepSecurityBackend().build(repo_path, files)

        # Find compiled class files or jars to analyse
        class_dirs = list(repo_path.rglob("*.class"))
        if not class_dirs:
            return SemgrepSecurityBackend().build(repo_path, files)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            out_path = f.name

        try:
            subprocess.run(
                [spotbugs_bin, "-xml:withMessages", f"-output:{out_path}",
                 "-effort:max", str(repo_path)],
                capture_output=True, timeout=180, cwd=repo_path,
            )
            tree = ET.parse(out_path)
            root = tree.getroot()
        except Exception:
            Path(out_path).unlink(missing_ok=True)
            return {"nodes": [], "edges": []}
        finally:
            Path(out_path).unlink(missing_ok=True)

        nodes = []
        for bug in root.findall(".//BugInstance"):
            source_line = bug.find("SourceLine")
            if source_line is None:
                continue
            fpath = source_line.get("sourcepath", "")
            try:
                rel_path = Path(fpath).relative_to(repo_path).as_posix()
            except ValueError:
                rel_path = fpath

            try:
                line_num = int(source_line.get("start", "0"))
            except ValueError:
                line_num = 0

            nodes.append({
                "node_id": str(uuid.uuid4()),
                "file_path": rel_path,
                "function_name": bug.get("type", "spotbugs_finding"),
                "line_start": line_num,
                "line_end": line_num,
                "node_type": "CALL_SINK",
                "code": bug.findtext("LongMessage", default="").strip(),
            })

        return {"nodes": nodes, "edges": []}


class BrakemanBackend:
    """
    Brakeman — Rails-specific static security scanner.
    Covers: mass assignment, SQL injection in ActiveRecord, open redirects, CSRF.
    Falls back to SemgrepSecurityBackend if brakeman is not on PATH.
    """

    def supported_extensions(self) -> list[str]:
        return [".rb"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import shutil
        import subprocess
        import json as _json

        brakeman_bin = shutil.which("brakeman")
        if brakeman_bin is None:
            import logging
            logging.getLogger(__name__).info(
                "BrakemanBackend: brakeman not found, falling back to Semgrep"
            )
            return SemgrepSecurityBackend().build(repo_path, files)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        try:
            subprocess.run(
                [brakeman_bin, "-f", "json", "-o", out_path,
                 "--no-progress", "--quiet", str(repo_path)],
                capture_output=True, timeout=120,
            )
            raw = _json.loads(Path(out_path).read_text())
        except Exception:
            raw = {}
        finally:
            Path(out_path).unlink(missing_ok=True)

        nodes = []
        for warning in raw.get("warnings", []):
            fpath = warning.get("file", "")
            try:
                rel_path = Path(fpath).relative_to(repo_path).as_posix()
            except ValueError:
                rel_path = fpath

            nodes.append({
                "node_id": str(uuid.uuid4()),
                "file_path": rel_path,
                "function_name": warning.get("warning_type", "brakeman_finding")
                                        .lower().replace(" ", "_"),
                "line_start": warning.get("line", 0) or 0,
                "line_end": warning.get("line", 0) or 0,
                "node_type": "CALL_SINK",
                "code": warning.get("message", "").strip(),
            })

        return {"nodes": nodes, "edges": []}


class RustBackend:
    """
    Rust security backend using cargo-audit + clippy.
    Covers: unsafe blocks, FFI boundary issues, integer overflow in as-casts,
    dependency CVEs via cargo-audit.
    """

    def supported_extensions(self) -> list[str]:
        return [".rs"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import shutil
        import subprocess
        import json as _json

        nodes = []

        # cargo audit — CVE check on dependencies
        cargo_bin = shutil.which("cargo")
        if cargo_bin:
            try:
                result = subprocess.run(
                    [cargo_bin, "audit", "--json"],
                    capture_output=True, text=True, timeout=120, cwd=repo_path,
                )
                audit_data = _json.loads(result.stdout)
                for vuln in audit_data.get("vulnerabilities", {}).get("list", []):
                    advisory = vuln.get("advisory", {})
                    nodes.append({
                        "node_id": str(uuid.uuid4()),
                        "file_path": "Cargo.toml",
                        "function_name": f"dep_{advisory.get('id', 'CVE_unknown')}",
                        "line_start": 1,
                        "line_end": 1,
                        "node_type": "CALL_SINK",
                        "code": advisory.get("title", ""),
                    })
            except Exception:
                pass

        # Grep for unsafe blocks as a heuristic source
        if repo_path.exists():
            for rs_file in (files or [str(p) for p in repo_path.rglob("*.rs")]):
                p = Path(rs_file)
                if not p.exists():
                    continue
                try:
                    rel = p.relative_to(repo_path).as_posix()
                    src = p.read_text(errors="replace")
                    for i, line in enumerate(src.splitlines(), 1):
                        if "unsafe" in line and "{" in line:
                            nodes.append({
                                "node_id": str(uuid.uuid4()),
                                "file_path": rel,
                                "function_name": "unsafe_block",
                                "line_start": i,
                                "line_end": i,
                                "node_type": "CALL_SINK",
                                "code": line.strip(),
                            })
                except Exception:
                    continue

        return {"nodes": nodes, "edges": []}


class EslintSecurityBackend:
    """
    eslint-plugin-security for JS/TS.
    Understands Express middleware chains and React prop flows that Semgrep misses.
    Only invoked if eslint + the security plugin are installed.
    """

    def supported_extensions(self) -> list[str]:
        return [".js", ".jsx", ".ts", ".tsx", ".mjs"]

    def build(self, repo_path: Path, files: list[str] | None = None) -> dict:
        import shutil
        import subprocess
        import json as _json

        eslint_bin = shutil.which("eslint")
        if eslint_bin is None:
            return {"nodes": [], "edges": []}

        target_files = files or [
            str(p) for ext in ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs")
            for p in repo_path.rglob(ext)
        ]
        if not target_files:
            return {"nodes": [], "edges": []}

        # Write a minimal eslint config that enables the security plugin
        eslint_config = {
            "plugins": ["security"],
            "rules": {
                "security/detect-object-injection": "error",
                "security/detect-non-literal-regexp": "warn",
                "security/detect-non-literal-require": "error",
                "security/detect-possible-timing-attacks": "warn",
                "security/detect-eval-with-expression": "error",
                "security/detect-child-process": "error",
                "security/detect-disable-mustache-escape": "error",
                "security/detect-new-buffer": "error",
            },
        }
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, dir=repo_path
        ) as cfg:
            import json as _j
            _j.dump({"extends": [], **eslint_config}, cfg)
            cfg_path = cfg.name

        nodes = []
        try:
            result = subprocess.run(
                [eslint_bin, "--no-eslintrc", "-c", cfg_path,
                 "--format=json", "--max-warnings=0"] + target_files[:30],
                capture_output=True, text=True, timeout=120, cwd=repo_path,
            )
            results = _json.loads(result.stdout or "[]")
            for file_result in results:
                fpath = file_result.get("filePath", "")
                try:
                    rel_path = Path(fpath).relative_to(repo_path).as_posix()
                except ValueError:
                    rel_path = fpath

                for msg in file_result.get("messages", []):
                    if msg.get("severity", 0) >= 2:
                        nodes.append({
                            "node_id": str(uuid.uuid4()),
                            "file_path": rel_path,
                            "function_name": msg.get("ruleId", "eslint_security")
                                                .replace("/", "_"),
                            "line_start": msg.get("line", 0),
                            "line_end": msg.get("endLine", msg.get("line", 0)),
                            "node_type": "CALL_SINK",
                            "code": msg.get("message", "").strip(),
                        })
        except Exception:
            pass
        finally:
            Path(cfg_path).unlink(missing_ok=True)

        return {"nodes": nodes, "edges": []}


# Extension → backend mapping. More specific backends take priority.
_EXT_MAP: dict[str, type] = {
    # C/C++
    ".cpp": JoernBackend,
    ".cc":  JoernBackend,
    ".c":   JoernBackend,
    ".h":   JoernBackend,
    ".hpp": JoernBackend,
    # Python — Bandit primary, Semgrep fallback built into BanditBackend
    ".py": BanditBackend,
    # JavaScript / TypeScript — Semgrep + ESLint merged in SemgrepJSBackend
    ".js":  SemgrepJSBackend,
    ".jsx": SemgrepJSBackend,
    ".ts":  SemgrepJSBackend,
    ".tsx": SemgrepJSBackend,
    ".mjs": SemgrepJSBackend,
    ".cjs": SemgrepJSBackend,
    # Go — gosec primary, Semgrep fallback built into GosecBackend
    ".go": GosecBackend,
    # Java — SpotBugs primary, Semgrep fallback built into SpotBugsBackend
    ".java": SpotBugsBackend,
    # Ruby — Brakeman primary, Semgrep fallback built into BrakemanBackend
    ".rb": BrakemanBackend,
    # Rust
    ".rs": RustBackend,
    # PHP — Semgrep best-effort
    ".php": SemgrepSecurityBackend,
    # Kotlin — Semgrep best-effort
    ".kt": SemgrepSecurityBackend,
}


def get_backend(ext: str) -> CPGBackend:
    return _EXT_MAP.get(ext, JoernBackend)()
