"""
vigilant/ingestion/cpg_builder.py
───────────────────────────────────
Builds and incrementally updates the Code Property Graph (CPG) in Neo4j.

Strategy:
  - FULL parse: invoked on the first run or on main-branch pushes.
    Joern is called via subprocess to generate the CPG, then nodes/edges
    are stored in Neo4j.
  - INCREMENTAL update: invoked on PR analysis. Only files that have
    changed (determined by SHA-256 content hash) are re-parsed. Stale
    nodes/edges for those functions are removed and replaced.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase, Driver

from vigilant.config import get_settings
from vigilant.models import CPGNode, CPGSummary

logger = logging.getLogger(__name__)

import threading

# ─────────────────────────────────────────────────────────────────────────────
# Neo4j helpers
# ─────────────────────────────────────────────────────────────────────────────

_driver: Driver | None = None
_driver_lock = threading.Lock()


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        with _driver_lock:
            if _driver is None:
                settings = get_settings()
                _driver = GraphDatabase.driver(
                    settings.neo4j_uri,
                    auth=(settings.neo4j_username, settings.neo4j_password),
                    max_connection_pool_size=50,
                    connection_timeout=30,
                    max_transaction_retry_time=15,
                )
                logger.info("Neo4j driver connected to %s", settings.neo4j_uri)
    return _driver


def close_driver() -> None:
    global _driver
    if _driver:
        _driver.close()
        _driver = None


# ─────────────────────────────────────────────────────────────────────────────
# Schema setup
# ─────────────────────────────────────────────────────────────────────────────

_schema_initialized = False


def reset_schema_flag() -> None:
    """Reset the schema initialization flag. Call this in test teardown when the
    Neo4j database is wiped between tests."""
    global _schema_initialized
    _schema_initialized = False

_SETUP_QUERIES = [
    # Constraints
    "CREATE CONSTRAINT cpg_node_unique IF NOT EXISTS FOR (n:CPGNode) REQUIRE n.node_id IS UNIQUE",
    "CREATE INDEX cpg_file_idx IF NOT EXISTS FOR (n:CPGNode) ON (n.file_path)",
    "CREATE INDEX cpg_func_idx IF NOT EXISTS FOR (n:CPGNode) ON (n.function_name)",
    "CREATE INDEX cpg_hash_idx IF NOT EXISTS FOR (n:CPGNode) ON (n.content_hash)",
]


def ensure_schema(driver: Driver) -> None:
    """Create Neo4j schema constraints and indexes if they don't exist."""
    global _schema_initialized
    if _schema_initialized:
        return

    with driver.session() as session:
        for query in _SETUP_QUERIES:
            try:
                session.run(query)
            except Exception as e:
                logger.debug("Schema setup skipped (may already exist): %s", e)
    _schema_initialized = True
    logger.info("Neo4j schema ready.")


# ─────────────────────────────────────────────────────────────────────────────
# Content hashing
# ─────────────────────────────────────────────────────────────────────────────


def hash_function_content(content: str) -> str:
    """SHA-256 of a function's source text. Used to detect changes."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def hash_file(path: Path) -> str:
    """SHA-256 of an entire file. Used for quick file-level change detection."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Joern invocation
# ─────────────────────────────────────────────────────────────────────────────


def _run_joern(repo_path: Path, files: list[str] | None = None) -> dict[str, Any]:
    """
    Invoke Joern to generate a CPG for the given repo (or subset of files).

    Returns a dict representing the CPG JSON produced by Joern's export.
    Falls back to a stub if Joern is not installed (for testing).
    """
    joern_bin = _find_joern()
    if joern_bin is None:
        logger.warning("Joern not found — returning stub CPG. Install Joern for real analysis.")
        return _stub_cpg(repo_path, files)

    with tempfile.TemporaryDirectory(prefix="joern_export_") as tmp:
        output_path = Path(tmp) / "cpg_export.json"
        cmd = [
            joern_bin,
            "--script", str(_joern_export_script()),
            "--param", f"repoPath={repo_path}",
            "--param", f"outputPath={output_path}",
        ]
        if files:
            cmd += ["--param", f"files={','.join(files)}"]

        logger.info("Running Joern: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            logger.error("Joern failed: %s", result.stderr)
            return {}

        if output_path.exists():
            return json.loads(output_path.read_text())
        return {}


def _find_joern() -> str | None:
    """Locate the joern binary on PATH or in the local joern/ directory."""
    import shutil
    local_joern = Path(__file__).parent.parent.parent / "joern" / "joern"
    if local_joern.exists():
        return str(local_joern)
    return shutil.which("joern") or shutil.which("joern-cli")


def _joern_export_script() -> Path:
    """Path to the bundled Joern export script (scripts/joern_export.sc)."""
    script_path = Path(__file__).parent.parent.parent / "scripts" / "joern_export.sc"
    if not script_path.exists():
        logger.warning(
            "Joern export script not found at %s. "
            "Copy scripts/joern_export.sc from the Vigilant-X repo.",
            script_path,
        )
    return script_path


def _stub_cpg(repo_path: Path, files: list[str] | None) -> dict[str, Any]:
    """
    Regex-based CPG stub used when Joern is unavailable.
    All file_path values are emitted as repo-relative POSIX strings to match
    the format used by changed_files throughout the pipeline.
    """
    import re

    SOURCES = {
        "argv", "scanf", "fgets", "read", "fread", "recv", "gets",
        "getenv", "SysAllocString", "SysAllocStringLen",
    }
    SINKS = {
        "memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
        "free", "memset", "memmove", "strncpy", "system", "delete",
        "SysFreeString", "CopyTo", "Attach", "Detach",
    }

    target_files = files or [
        str(p) for ext in ("*.cpp", "*.cc", "*.c", "*.h")
        for p in repo_path.rglob(ext)
    ]

    nodes: list[dict] = []
    edges: list[dict] = []
    func_name_to_id: dict[str, str] = {}
    file_parse_cache: dict[str, tuple[str, list]] = {}

    def _rel(path_obj: Path) -> str:
        """Always return a repo-relative POSIX string."""
        try:
            return path_obj.relative_to(repo_path).as_posix()
        except ValueError:
            return path_obj.as_posix()

    FUNC_RE = re.compile(
        r"(?:template\s*<[^>]+>\s*)?"
        r"(?:\w[\w\s\*&<>]+\s+)"
        r"(?P<name>\w+)"
        r"\s*\([^)]*\)"
        r"(?:\s*const)?(?:\s*override)?(?:\s*noexcept)?"
        r"\s*\{",
        re.MULTILINE,
    )

    # Pass 1: find all functions
    for fpath in target_files:
        p = Path(fpath)
        if not p.exists():
            continue
        src_text = p.read_text(errors="replace")
        rel = _rel(p)
        matches = []

        for match in FUNC_RE.finditer(src_text):
            line_start = src_text[: match.start()].count("\n") + 1
            body_start = match.end() - 1
            body_text = src_text[body_start:]
            depth, end_idx = 0, len(body_text) - 1
            for i, ch in enumerate(body_text):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_idx = i
                        break
            body = body_text[: end_idx + 1]
            line_end = line_start + body.count("\n")

            func_id = str(uuid.uuid4())
            fname = match.group("name")
            func_name_to_id[fname] = func_id
            nodes.append({
                "node_id": func_id,
                "file_path": rel,          # <-- repo-relative POSIX
                "function_name": fname,
                "line_start": line_start,
                "line_end": line_end,
                "node_type": "AST_FUNC",
                "code": (match.group(0) + body)[:2000],
            })
            matches.append((match, fname, func_id, body, line_start))
        file_parse_cache[fpath] = (src_text, matches)

    # Pass 2: find sources, sinks, internal calls
    for fpath in target_files:
        if fpath not in file_parse_cache:
            continue
        src_text, matches = file_parse_cache[fpath]
        p = Path(fpath)
        rel = _rel(p)

        for match, fname, func_id, body, line_start in matches:
            # argv access
            for m in re.finditer(r"\bargv\[\d+\]", body):
                cid = str(uuid.uuid4())
                cline = line_start + body[: m.start()].count("\n")
                nodes.append({
                    "node_id": cid,
                    "file_path": rel,      # <-- repo-relative POSIX
                    "function_name": "argv",
                    "line_start": cline,
                    "line_end": cline,
                    "node_type": "CALL_SOURCE",
                    "code": m.group(0),
                })
                edges.append({"src": cid, "dst": func_id, "type": "CALL"})

            # function calls
            for call in re.finditer(r"\b(\w+)\s*\(", body):
                cname = call.group(1)
                cline = line_start + body[: call.start()].count("\n")
                cid = str(uuid.uuid4())

                node_type = "CALL"
                if cname in SOURCES:
                    node_type = "CALL_SOURCE"
                elif cname in SINKS:
                    node_type = "CALL_SINK"

                nodes.append({
                    "node_id": cid,
                    "file_path": rel,      # <-- repo-relative POSIX
                    "function_name": cname,
                    "line_start": cline,
                    "line_end": cline,
                    "node_type": node_type,
                    "code": call.group(0),
                })

                if node_type == "CALL_SOURCE":
                    edges.append({"src": cid, "dst": func_id, "type": "CALL"})
                else:
                    edges.append({"src": func_id, "dst": cid, "type": "CALL"})

                if cname in func_name_to_id:
                    edges.append({
                        "src": cid,
                        "dst": func_name_to_id[cname],
                        "type": "CALL",
                    })

    return {"nodes": nodes, "edges": edges}



# ─────────────────────────────────────────────────────────────────────────────
# Stable repo ID
# ─────────────────────────────────────────────────────────────────────────────


def _stable_repo_id(repo_path: Path) -> str:
    """
    Derive a stable repository identifier that survives CI workspace changes.

    Priority order:
    1. Git remote URL (most stable — survives renames and re-clones).
    2. Git repository root path hash (stable within one machine if no remote).
    3. Fallback to resolved path hash (original behaviour).
    """
    import subprocess
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            remote_url = result.stdout.strip()
            return hashlib.sha256(remote_url.encode()).hexdigest()[:16]
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            root = result.stdout.strip()
            return hashlib.sha256(root.encode()).hexdigest()[:16]
    except Exception:
        pass

    return hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# CPG Builder — public interface
# ─────────────────────────────────────────────────────────────────────────────


class CPGBuilder:
    """
    Manages full and incremental CPG builds.

    Full build: parse entire repo → write all nodes/edges to Neo4j.
    Incremental: for each changed file, compare SHA-256 hashes of functions,
                 delete stale nodes, and insert new/modified ones only.
    """

    def __init__(self) -> None:
        self.driver = get_driver()
        ensure_schema(self.driver)

    # ── Public API ────────────────────────────────────────────────────────────

    def build_cpg(
        self,
        repo_path: Path,
        changed_files: list[str],
        base_commit: str = "",
        force_full: bool = False,
    ) -> CPGSummary:
        """Entry point for PR-scoped or full codebase ingestion."""
        run_id = uuid.uuid4().hex
        repo_id = _stable_repo_id(repo_path)
        if force_full or not self._has_existing_cpg(repo_id):
            return self._full_parse(repo_path, run_id=run_id, repo_id=repo_id)

        from vigilant.ingestion.backends import get_backend
        # Group files by backend type for efficient batching
        by_backend: dict[str, tuple[Any, list[str]]] = {}
        for f in changed_files:
            ext = Path(f).suffix
            backend = get_backend(ext)
            backend_name = type(backend).__name__
            if backend_name not in by_backend:
                by_backend[backend_name] = (backend, [])
            by_backend[backend_name][1].append(f)

        # Process each group
        total = CPGSummary(ingestion_mode="incremental")
        for backend_name, (backend, files) in by_backend.items():
            logger.info("CPG: Using backend %s for files: %s", backend_name, files)
            result = self._incremental_update(repo_path, files, backend=backend, run_id=run_id, repo_id=repo_id)
            total.nodes_created += result.nodes_created
            total.edges_created += result.edges_created
        return total
    # ── Full parse ────────────────────────────────────────────────────────────

    def _full_parse(self, repo_path: Path, run_id: str, repo_id: str = "") -> CPGSummary:
        raw_cpg = _run_joern(repo_path)
        nodes = raw_cpg.get("nodes", [])
        edges = raw_cpg.get("edges", [])

        # Map local Joern IDs to global unique IDs
        id_map: dict[str, str] = {}
        for node_data in nodes:
            local_id = str(node_data.get("node_id", ""))
            rel_path = node_data.get("file_path", "")
            if local_id:
                global_id = hashlib.sha256(f"{repo_id}:{rel_path}:{local_id}".encode()).hexdigest()
                id_map[local_id] = global_id
                node_data["node_id"] = global_id

        for edge in edges:
            src_local = str(edge.get("src", ""))
            dst_local = str(edge.get("dst", ""))
            if src_local in id_map:
                edge["src"] = id_map[src_local]
            if dst_local in id_map:
                edge["dst"] = id_map[dst_local]

        created = 0
        with self.driver.session() as session:
            for node_data in nodes:
                code_text = node_data.get("code", "")
                content_hash = hash_function_content(code_text)
                session.run(
                    """
                    MERGE (n:CPGNode {node_id: $node_id})
                    SET n += {
                        file_path: $file_path,
                        function_name: $function_name,
                        line_start: $line_start,
                        line_end: $line_end,
                        node_type: $node_type,
                        code: $code,
                        content_hash: $content_hash,
                        run_id: $rid,
                        repo_id: $repo_id
                    }
                    """,
                    node_id=node_data.get("node_id", str(uuid.uuid4())),
                    file_path=node_data.get("file_path", ""),
                    function_name=node_data.get("function_name", ""),
                    line_start=int(node_data.get("line_start", 0)),
                    line_end=int(node_data.get("line_end", 0)),
                    node_type=node_data.get("node_type", "AST_FUNC"),
                    code=code_text,
                    content_hash=content_hash,
                    rid=run_id,
                    repo_id=repo_id,
                )
                created += 1

            edge_count = self._write_edges(session, edges)

            # Delete stale nodes for THIS repository only
            session.run(
                "MATCH (n:CPGNode) WHERE n.repo_id = $repo_id AND n.run_id <> $rid DETACH DELETE n",
                rid=run_id,
                repo_id=repo_id,
            )

        return CPGSummary(
            nodes_created=created,
            edges_created=edge_count,
            ingestion_mode="full",
        )

    # ── Incremental update ────────────────────────────────────────────────────

    def _incremental_update(self, repo_path: Path, changed_files: list[str], backend: Any = None, run_id: str = "", repo_id: str = "") -> CPGSummary:
        created = edge_count = 0
        from vigilant.ingestion.backends import JoernBackend
        if backend is None:
            backend = JoernBackend()

        def _process(rel_path: str) -> tuple[int, int]:
            self._delete_file_nodes(rel_path, repo_id)
            abs_path = repo_path / rel_path
            if not abs_path.exists():
                return 0, 0
            
            raw = backend.build(repo_path, files=[str(abs_path)])
            nodes_data = raw.get("nodes", [])
            id_map: dict[str, str] = {}
            for nd in nodes_data:
                local_id = str(nd.get("node_id", ""))
                if local_id:
                    global_id = hashlib.sha256(f"{repo_id}:{rel_path}:{local_id}".encode()).hexdigest()
                    id_map[local_id] = global_id
                    nd["node_id"] = global_id
            for e in raw.get("edges", []):
                if str(e.get("src","")) in id_map: e["src"] = id_map[str(e["src"])]
                if str(e.get("dst","")) in id_map: e["dst"] = id_map[str(e["dst"])]
            n_count = e_count = 0
            with self.driver.session() as session:
                for nd in nodes_data:
                    code = nd.get("code", "")
                    session.run(
                        "MERGE (n:CPGNode {node_id:$nid}) SET n += {file_path:$fp,"
                        "function_name:$fn,line_start:$ls,line_end:$le,node_type:$nt,"
                        "code:$code,content_hash:$ch,run_id:$rid,repo_id:$repo_id}",
                        nid=nd.get("node_id", str(uuid.uuid4())), fp=rel_path,
                        fn=nd.get("function_name",""), ls=int(nd.get("line_start",0)),
                        le=int(nd.get("line_end",0)), nt=nd.get("node_type","AST_FUNC"),
                        code=code, ch=hash_function_content(code), rid=run_id, repo_id=repo_id,
                    )
                    n_count += 1
                e_count = self._write_edges(session, raw.get("edges", []))
            return n_count, e_count

        # Cap workers to avoid saturating the Neo4j connection pool
        workers = min(4, len(changed_files))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_process, f): f for f in changed_files}
            for fut in as_completed(futures):
                try:
                    n, e = fut.result()
                    created += n; edge_count += e
                except Exception as exc:
                    logger.error("Ingestion failed for %s: %s", futures[fut], exc)

        return CPGSummary(nodes_created=created, edges_created=edge_count, ingestion_mode="incremental")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _has_existing_cpg(self, repo_id: str) -> bool:
        with self.driver.session() as session:
            result = session.run("MATCH (n:CPGNode {repo_id: $rid}) RETURN count(n) AS cnt", rid=repo_id)
            record = result.single()
            return bool(record and record["cnt"] > 0)

    def _delete_file_nodes(self, file_path: str, repo_id: str) -> None:
        with self.driver.session() as session:
            session.run(
                "MATCH (n:CPGNode {file_path: $fp, repo_id: $rid}) DETACH DELETE n",
                fp=file_path, rid=repo_id,
            )
        logger.info("CPG: deleted nodes for removed file %s", file_path)

    def _write_edges(self, session: Any, edges: list[dict]) -> int:
        count = 0
        by_type: dict[str, list[tuple[str, str]]] = {}
        for edge in edges:
            etype = edge.get("type", "CALL").upper()
            src, dst = edge.get("src", ""), edge.get("dst", "")
            if src and dst:
                by_type.setdefault(etype, []).append((src, dst))

        for etype, pairs in by_type.items():
            try:
                session.run(
                    """
                    UNWIND $pairs AS pair
                    MATCH (a:CPGNode {node_id: pair[0]})
                    MATCH (b:CPGNode {node_id: pair[1]})
                    CALL apoc.merge.relationship(a, $etype, {}, {}, b, {}) YIELD rel
                    RETURN count(*)
                    """,
                    pairs=pairs, etype=etype,
                )
                count += len(pairs)
            except Exception:
                # APOC absent — fall back to per-pair MERGE with dynamic rel type.
                # Sanitise etype to prevent injection (only A-Z _ allowed after uppercasing).
                safe = "".join(c for c in etype if c.isalpha() or c == "_")
                for src, dst in pairs:
                    try:
                        session.run(
                            f"MATCH (a:CPGNode {{node_id:$s}}) "
                            f"MATCH (b:CPGNode {{node_id:$d}}) "
                            f"MERGE (a)-[:`{safe}`]->(b)",
                            s=src, d=dst,
                        )
                        count += 1
                    except Exception as e2:
                        logger.warning("Edge write failed %s→%s: %s", src, dst, e2)
        return count
    def get_node(self, node_id: str) -> dict[str, Any] | None:
        with self.driver.session() as session:
            result = session.run(
                "MATCH (n:CPGNode {node_id: $id}) RETURN n",
                id=node_id,
            )
            record = result.single()
            return record["n"] if record else None

    # ── Query helpers (used by TaintTracker) ─────────────────────────────────

    def get_nodes_for_file(self, file_path: str) -> list[CPGNode]:
        with self.driver.session() as session:
            result = session.run(
                "MATCH (n:CPGNode {file_path: $fp}) RETURN n",
                fp=file_path,
            )
            nodes = []
            for record in result:
                n = record["n"]
                nodes.append(CPGNode(
                    node_id=n["node_id"],
                    file_path=n["file_path"],
                    function_name=n["function_name"],
                    line_start=n.get("line_start", 0),
                    line_end=n.get("line_end", 0),
                    node_type=n.get("node_type", "AST_FUNC"),
                    content_hash=n.get("content_hash", ""),
                ))
            return nodes
