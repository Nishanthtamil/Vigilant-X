"""
vigilant/analysis/taint_tracker.py
────────────────────────────────────
Queries the Neo4j CPG to find source→sink taint paths across file boundaries.

Uses Neo4j APOC path-finding procedures (apoc.path.expandConfig, apoc.algo.dijkstra)
to push graph traversal to the server — avoiding expensive node pulls over the
network for large codebases.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from neo4j import Driver

from vigilant.config import CodeLaw, RuleSeverity, get_settings
from vigilant.ingestion.cpg_builder import get_driver
from vigilant.models import TaintNode, TaintPath

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Source and Sink definitions
# ─────────────────────────────────────────────────────────────────────────────

# Sources: user-controlled data entry points
TAINT_SOURCES = [
    # OS/Shell input
    "argv", "getenv", "read", "fread", "recv", "recvfrom", "recvmsg",
    "scanf", "fscanf", "sscanf", "fgets", "gets", "getline",
    "readlink", "getopt", "getopt_long",
    # Uninitialized allocations (sources of uninit data)
    "malloc", "calloc", "realloc", "mmap",
    # Modern C++ sources
    "std::cin", "std::ifstream", "std::getline",
    "std::unique_ptr::release",  # source for use-after-free tracking
]

# Sinks: potentially dangerous functions
TAINT_SINKS = [
    # Buffer overflow/memory safety
    "memcpy", "memmove", "memset", "memccpy", "memalign",
    "strcpy", "strcat", "sprintf", "vsprintf", "snprintf",
    "strcpy", "strncpy", "strncat", "strtok",
    # Command/System injection
    "system", "popen", "exec", "execve", "execl", "execv", "execvp",
    # Memory management (sinks for double-free/UAF)
    "free", "delete", "operator delete",
    "std::unique_ptr::reset",
    # Threading/Concurrency (sinks for data races)
    "std::thread", "pthread_create", "fork",
]

# ─────────────────────────────────────────────────────────────────────────────
# APOC Queries
# ─────────────────────────────────────────────────────────────────────────────

# Finds all paths from any source node to any sink node using APOC's
# server-side path expansion. Now prioritizes PDG (REACHING_DEF) and CALL edges.
_APOC_PATH_QUERY = """
MATCH (source:CPGNode)
WHERE any(s IN $sources WHERE source.function_name CONTAINS s)

MATCH (sink:CPGNode)
WHERE any(sk IN $sinks WHERE sink.function_name CONTAINS sk)

CALL apoc.path.expandConfig(source, {
    relationshipFilter: "CALL>|REACHING_DEF>|REF>",
    minLevel: 1,
    maxLevel: 20,
    terminatorNodes: [sink],
    uniqueness: "NODE_PATH"
})
YIELD path
WHERE last(nodes(path)).node_id = sink.node_id

RETURN
    source.node_id   AS src_id,
    source.file_path AS src_file,
    source.function_name AS src_func,
    source.line_start AS src_line,
    sink.node_id     AS snk_id,
    sink.file_path   AS snk_file,
    sink.function_name AS snk_func,
    sink.line_start  AS snk_line,
    [n IN nodes(path) | {
        node_id: n.node_id,
        file_path: n.file_path,
        function_name: n.function_name,
        line_number: n.line_start
    }] AS path_nodes,
    length(path)     AS path_len
ORDER BY path_len ASC
LIMIT 100
"""

# Fallback query using modern labels
_FALLBACK_PATH_QUERY = """
MATCH path = (source:CPGNode)-[:CALL|REACHING_DEF|REF*1..15]->(sink:CPGNode)
WHERE any(s IN $sources WHERE source.function_name CONTAINS s)
  AND any(sk IN $sinks WHERE sink.function_name CONTAINS sk)
RETURN
    source.node_id AS src_id,
    source.file_path AS src_file,
    source.function_name AS src_func,
    source.line_start AS src_line,
    sink.node_id AS snk_id,
    sink.file_path AS snk_file,
    sink.function_name AS snk_func,
    sink.line_start AS snk_line,
    [n IN nodes(path) | {
        node_id: n.node_id,
        file_path: n.file_path,
        function_name: n.function_name,
        line_number: n.line_start
    }] AS path_nodes,
    length(path) AS path_len
ORDER BY path_len ASC
LIMIT 100
"""


# ─────────────────────────────────────────────────────────────────────────────
# TaintTracker
# ─────────────────────────────────────────────────────────────────────────────


class TaintTracker:
    """
    Queries the Neo4j CPG to enumerate all source→sink taint paths.

    Prefers APOC server-side traversal for performance; falls back to
    pure Cypher if APOC is not installed.
    """

    def __init__(self, driver: Driver | None = None, code_law: CodeLaw | None = None) -> None:
        self.driver = driver or get_driver()
        self.code_law = code_law or CodeLaw()
        self._apoc_available: bool | None = None   # lazy check

    # ── Public API ────────────────────────────────────────────────────────────

    def find_taint_paths(
        self,
        extra_sources: list[str] | None = None,
        extra_sinks: list[str] | None = None,
    ) -> list[TaintPath]:
        """
        Walk the CPG and return all source→sink taint paths.

        Args:
            extra_sources: Additional source patterns from Code Law rules.
            extra_sinks: Additional sink patterns from Code Law rules.
        """
        sources = list(TAINT_SOURCES) + (extra_sources or [])
        sinks = list(TAINT_SINKS) + (extra_sinks or [])

        logger.info(
            "TaintTracker: searching %d sources × %d sinks via %s",
            len(sources), len(sinks),
            "APOC" if self._check_apoc() else "Cypher fallback",
        )

        query = _APOC_PATH_QUERY if self._check_apoc() else _FALLBACK_PATH_QUERY
        raw_paths = self._run_query(query, {"sources": sources, "sinks": sinks})
        paths = [self._to_taint_path(r) for r in raw_paths]

        # Annotate with Code Law rule metadata
        paths = self._annotate_with_code_law(paths)

        logger.info("TaintTracker: found %d taint paths", len(paths))
        return paths

    # ── APOC availability check ───────────────────────────────────────────────

    def _check_apoc(self) -> bool:
        if self._apoc_available is not None:
            return self._apoc_available
        try:
            with self.driver.session() as session:
                result = session.run("RETURN apoc.version() AS ver")
                ver = result.single()
                self._apoc_available = ver is not None
                if self._apoc_available:
                    logger.info("APOC available (v%s) — using server-side path expansion", ver["ver"])
                else:
                    logger.warning("APOC not available — falling back to pure Cypher path query")
        except Exception:
            self._apoc_available = False
            logger.warning("APOC check failed — falling back to pure Cypher path query")
        return self._apoc_available  # type: ignore[return-value]

    # ── Query execution ───────────────────────────────────────────────────────

    def _run_query(self, query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            with self.driver.session() as session:
                result = session.run(query, **params)
                return [record.data() for record in result]
        except Exception as e:
            logger.error("TaintTracker query failed: %s", e)
            return []

    # ── Model conversion ──────────────────────────────────────────────────────

    @staticmethod
    def _to_taint_path(record: dict[str, Any]) -> TaintPath:
        src = TaintNode(
            node_id=record["src_id"] or str(uuid.uuid4()),
            file_path=record["src_file"] or "",
            function_name=record["src_func"] or "",
            line_number=record.get("src_line") or 0,
            node_role="SOURCE",
            label=record["src_func"] or "",
        )
        snk = TaintNode(
            node_id=record["snk_id"] or str(uuid.uuid4()),
            file_path=record["snk_file"] or "",
            function_name=record["snk_func"] or "",
            line_number=record.get("snk_line") or 0,
            node_role="SINK",
            label=record["snk_func"] or "",
        )
        intermediates = []
        path_nodes: list[dict] = record.get("path_nodes", []) or []
        for node in path_nodes[1:-1]:   # skip first (source) and last (sink)
            intermediates.append(TaintNode(
                node_id=node.get("node_id", str(uuid.uuid4())),
                file_path=node.get("file_path", ""),
                function_name=node.get("function_name", ""),
                line_number=node.get("line_number", 0),
                node_role="INTERMEDIATE",
                label=node.get("function_name", ""),
            ))

        crosses_files = src.file_path != snk.file_path

        return TaintPath(
            path_id=str(uuid.uuid4()),
            source=src,
            sink=snk,
            intermediate_nodes=intermediates,
            crosses_files=crosses_files,
        )

    # ── Code Law annotation ───────────────────────────────────────────────────

    def _annotate_with_code_law(self, paths: list[TaintPath]) -> list[TaintPath]:
        """
        Match each path's sink function against Code Law rules and annotate
        the path with the matching rule_id and severity.
        """
        for path in paths:
            for rule in self.code_law.rules:
                if any(
                    sink_kw in path.sink.function_name
                    for sink_kw in rule.pattern.split("|")
                    if sink_kw.startswith("call:")
                ):
                    path.rule_id = rule.id
                    path.rule_severity = rule.severity.value
                    break
            # Default CRITICAL for memory-safety sinks with no explicit rule
            if not path.rule_id:
                path.rule_severity = RuleSeverity.CRITICAL.value
        return paths
