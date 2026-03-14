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
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase, Driver

from vigilant.config import get_settings
from vigilant.models import CPGNode, CPGSummary

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Neo4j helpers
# ─────────────────────────────────────────────────────────────────────────────

_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        settings = get_settings()
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_username, settings.neo4j_password),
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

_SETUP_QUERIES = [
    # Constraints
    "CREATE CONSTRAINT cpg_node_unique IF NOT EXISTS FOR (n:CPGNode) REQUIRE n.node_id IS UNIQUE",
    "CREATE INDEX cpg_file_idx IF NOT EXISTS FOR (n:CPGNode) ON (n.file_path)",
    "CREATE INDEX cpg_func_idx IF NOT EXISTS FOR (n:CPGNode) ON (n.function_name)",
    "CREATE INDEX cpg_hash_idx IF NOT EXISTS FOR (n:CPGNode) ON (n.content_hash)",
]


def ensure_schema(driver: Driver) -> None:
    """Create Neo4j schema constraints and indexes if they don't exist."""
    with driver.session() as session:
        for query in _SETUP_QUERIES:
            try:
                session.run(query)
            except Exception as e:
                logger.debug("Schema setup skipped (may already exist): %s", e)
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
    When Joern is unavailable, scan the repo with regex heuristics to produce
    a minimal CPG stub. Emits:
    - AST_FUNC nodes for each function definition
    - CALL_SOURCE nodes for user-input call-sites (argv, scanf, read, fgets...)
    - CALL_SINK  nodes for dangerous call-sites (memcpy, strcpy, free, ...)
    - CALL edges: SOURCE -> enclosing-function -> SINK and FUNC -> FUNC
    """
    import re

    SOURCES = {"argv", "scanf", "fgets", "read", "fread", "recv", "gets", "getenv"}
    SINKS   = {
        "memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
        "free", "memset", "memmove", "strncpy", "system", "delete",
    }

    target_files = files or [
        str(p) for ext in ("*.cpp", "*.cc", "*.c", "*.h")
        for p in repo_path.rglob(ext)
    ]

    nodes: list[dict] = []
    edges: list[dict] = []
    func_name_to_id: dict[str, str] = {}

    # Pass 1: find all functions
    for fpath in target_files:
        p = Path(fpath)
        if not p.exists(): continue
        src_text = p.read_text(errors="replace")

        for match in re.finditer(
            r"(?P<ret>\w[\w\s\*&]+)\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{",
            src_text,
        ):
            line_start = src_text[: match.start()].count("\n") + 1
            body_text = src_text[match.start():]
            depth, end_idx = 0, len(body_text) - 1
            for i, ch in enumerate(body_text):
                if ch == "{": depth += 1
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
                "file_path": str(p.relative_to(repo_path) if p.is_relative_to(repo_path) else p),
                "function_name": fname,
                "line_start": line_start,
                "line_end": line_end,
                "node_type": "AST_FUNC",
                "code": body[:800],
            })

    # Pass 2: find sources, sinks, and internal calls
    for fpath in target_files:
        p = Path(fpath)
        if not p.exists(): continue
        src_text = p.read_text(errors="replace")

        for match in re.finditer(
            r"(?P<ret>\w[\w\s\*&]+)\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{",
            src_text,
        ):
            fname = match.group("name")
            func_id = func_name_to_id.get(fname)
            if not func_id: continue

            body_text = src_text[match.start():]
            depth, end_idx = 0, len(body_text) - 1
            for i, ch in enumerate(body_text):
                if ch == "{": depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_idx = i
                        break
            body = body_text[: end_idx + 1]
            line_start = src_text[: match.start()].count("\n") + 1

            # Find argv access (common source)
            for m in re.finditer(r"\bargv\[\d+\]", body):
                cid = str(uuid.uuid4())
                cline = line_start + body[: m.start()].count("\n")
                nodes.append({
                    "node_id": cid, "file_path": str(p.relative_to(repo_path) if p.is_relative_to(repo_path) else p),
                    "function_name": "argv", "line_start": cline, "line_end": cline,
                    "node_type": "CALL_SOURCE", "code": m.group(0),
                })
                edges.append({"src": cid, "dst": func_id, "type": "CALL"})

            # Find calls
            for call in re.finditer(r"\b(\w+)\s*\(", body):
                cname = call.group(1)
                cline = line_start + body[: call.start()].count("\n")
                cid = str(uuid.uuid4())

                if cname in SOURCES:
                    nodes.append({
                        "node_id": cid, "file_path": str(p.relative_to(repo_path) if p.is_relative_to(repo_path) else p),
                        "function_name": cname, "line_start": cline, "line_end": cline,
                        "node_type": "CALL_SOURCE", "code": call.group(0),
                    })
                    edges.append({"src": cid, "dst": func_id, "type": "CALL"})
                elif cname in SINKS:
                    nodes.append({
                        "node_id": cid, "file_path": str(p.relative_to(repo_path) if p.is_relative_to(repo_path) else p),
                        "function_name": cname, "line_start": cline, "line_end": cline,
                        "node_type": "CALL_SINK", "code": call.group(0),
                    })
                    edges.append({"src": func_id, "dst": cid, "type": "CALL"})
                elif cname in func_name_to_id:
                    # Internal function call
                    edges.append({"src": func_id, "dst": func_name_to_id[cname], "type": "CALL"})

    return {"nodes": nodes, "edges": edges}



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
        """
        Entry point. Chooses full vs incremental strategy automatically.

        Args:
            repo_path: Absolute path to the checked-out repo.
            changed_files: Files changed in the PR (relative paths).
            base_commit: The base commit SHA (used to determine if DB is populated).
            force_full: If True, always do a full re-parse.
        """
        if force_full or not self._has_existing_cpg():
            logger.info("CPG: full parse mode")
            return self._full_parse(repo_path)
        else:
            logger.info("CPG: incremental update for %d files", len(changed_files))
            return self._incremental_update(repo_path, changed_files)

    # ── Full parse ────────────────────────────────────────────────────────────

    def _full_parse(self, repo_path: Path) -> CPGSummary:
        raw_cpg = _run_joern(repo_path)
        nodes = raw_cpg.get("nodes", [])
        edges = raw_cpg.get("edges", [])

        created = 0
        with self.driver.session() as session:
            # Clear existing graph
            session.run("MATCH (n:CPGNode) DETACH DELETE n")
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
                        content_hash: $content_hash
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
                )
                created += 1

            edge_count = self._write_edges(session, edges)

        return CPGSummary(
            nodes_created=created,
            edges_created=edge_count,
            ingestion_mode="full",
        )

    # ── Incremental update ────────────────────────────────────────────────────

    def _incremental_update(self, repo_path: Path, changed_files: list[str]) -> CPGSummary:
        """
        For each changed file:
        1. Parse with Joern (file-scoped).
        2. For each node in the new parse, compute SHA-256 (if it's a function).
        3. Compare with the hash stored in Neo4j.
        4. Delete stale nodes, insert new/modified nodes only.
        """
        created = updated = unchanged = edge_count = 0

        for rel_path in changed_files:
            abs_path = repo_path / rel_path
            if not abs_path.exists():
                # File deleted — remove its nodes
                self._delete_file_nodes(rel_path)
                continue

            raw_cpg = _run_joern(repo_path, files=[str(abs_path)])
            new_nodes = raw_cpg.get("nodes", [])
            new_edges = raw_cpg.get("edges", [])

            with self.driver.session() as session:
                for node_data in new_nodes:
                    node_type = node_data.get("node_type", "AST_FUNC")
                    code_text = node_data.get("code", "")
                    new_hash = hash_function_content(code_text)
                    
                    # For Joern nodes, node_id is stable within a parse session but might 
                    # change across sessions. However, file_path + line_start + node_type 
                    # is a decent heuristic for node identity in incremental updates.
                    node_id = node_data.get("node_id")
                    
                    existing = session.run(
                        """
                        MATCH (n:CPGNode {file_path: $fp, node_type: $nt, line_start: $ls, function_name: $fn}) 
                        RETURN n.content_hash AS h
                        """,
                        fp=rel_path, nt=node_type, ls=int(node_data.get("line_start", 0)),
                        fn=node_data.get("function_name", "")
                    ).single()

                    if existing and existing["h"] == new_hash:
                        unchanged += 1
                        continue

                    # Upsert the node
                    session.run(
                        """
                        MERGE (n:CPGNode {file_path: $file_path, node_type: $node_type, line_start: $line_start, function_name: $function_name})
                        SET n += {
                            node_id: $node_id,
                            line_end: $line_end,
                            code: $code,
                            content_hash: $content_hash
                        }
                        """,
                        node_id=node_id,
                        file_path=rel_path,
                        node_type=node_type,
                        line_start=int(node_data.get("line_start", 0)),
                        function_name=node_data.get("function_name", ""),
                        line_end=int(node_data.get("line_end", 0)),
                        code=code_text,
                        content_hash=new_hash,
                    )
                    if existing:
                        updated += 1
                    else:
                        created += 1

                # Write edges for this file's updated nodes
                edge_count += self._write_edges(session, new_edges)

        return CPGSummary(
            nodes_created=created,
            nodes_updated=updated,
            nodes_unchanged=unchanged,
            edges_created=edge_count,
            ingestion_mode="incremental",
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _has_existing_cpg(self) -> bool:
        with self.driver.session() as session:
            result = session.run("MATCH (n:CPGNode) RETURN count(n) AS cnt")
            record = result.single()
            return bool(record and record["cnt"] > 0)

    def _delete_file_nodes(self, file_path: str) -> None:
        with self.driver.session() as session:
            session.run(
                "MATCH (n:CPGNode {file_path: $fp}) DETACH DELETE n",
                fp=file_path,
            )
        logger.info("CPG: deleted nodes for removed file %s", file_path)

    def _write_edges(self, session: Any, edges: list[dict]) -> int:
        count = 0
        # Group edges by type to run batch MERGE queries
        by_type: dict[str, list[tuple[str, str]]] = {}
        for edge in edges:
            etype = edge.get("type", "CALL").upper()
            src = edge.get("src", "")
            dst = edge.get("dst", "")
            if src and dst:
                by_type.setdefault(etype, []).append((src, dst))

        for etype, pairs in by_type.items():
            # Neo4j doesn't allow parameterized relationship types, 
            # so we use APOC to merge with dynamic types safely.
            session.run(
                """
                UNWIND $pairs AS pair
                MATCH (a:CPGNode {node_id: pair[0]})
                MATCH (b:CPGNode {node_id: pair[1]})
                CALL apoc.merge.relationship(a, $etype, {}, {}, b, {})
                YIELD rel
                RETURN count(*)
                """,
                pairs=pairs,
                etype=etype
            )
            count += len(pairs)
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
