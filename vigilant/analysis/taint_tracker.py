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
    # COM/BSTR sources
    "SysAllocString", "SysAllocStringLen", "SysAllocStringByteLen",
    "CoTaskMemAlloc",
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
    # Memory management (sinks for double-free/UAF/Leaks)
    "free", "delete", "operator delete",
    "SysFreeString", "CoTaskMemFree",
    "CopyTo", "Attach", "Detach", # CComBSTR / CComPtr sinks
    "std::unique_ptr::reset",
    # Threading/Concurrency (sinks for data races)
    "std::thread", "pthread_create", "fork",
]

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
        pr_intent: Any | None = None,
        extra_sources: list[str] | None = None,
        extra_sinks: list[str] | None = None,
        changed_files: list[str] | None = None,
    ) -> list[TaintPath]:
        """
        Walk the CPG and return all source→sink taint paths.

        Args:
            pr_intent: PRIntent containing dynamically detected sinks.
            extra_sources: Additional source patterns from Code Law rules.
            extra_sinks: Additional sink patterns from Code Law rules.
            changed_files: List of relative paths to only start analysis from.
        """
        sources = list(TAINT_SOURCES) + (extra_sources or [])
        sinks = list(TAINT_SINKS) + (extra_sinks or [])

        # Add dynamic sources/sinks from intent parser
        if pr_intent:
            sources.extend(getattr(pr_intent, "dynamic_sources", []))
            sinks.extend(getattr(pr_intent, "dynamic_sinks", []))

        self._bridge_opaque_binaries()
        self._resolve_virtual_calls()

        logger.info(
            "TaintTracker: searching %d sources × %d sinks via %s (scoped: %s)",
            len(sources), len(sinks),
            "APOC" if self._check_apoc() else "Cypher fallback",
            "yes" if changed_files else "no"
        )

        query = self._get_query(changed_files is not None)
        raw_paths = self._run_query(query, {
            "sources": sources,
            "sinks": sinks,
            "changed_files": changed_files or [],
            "scoped": changed_files is not None,
        })
        paths = [self._to_taint_path(r) for r in raw_paths]

        # Annotate with Code Law rule metadata
        paths = self._annotate_with_code_law(paths)

        logger.info("TaintTracker: found %d taint paths", len(paths))
        return paths

    def _get_query(self, scoped: bool) -> str:
        base_apoc = """
MATCH (source:CPGNode)
WHERE source.function_name IN $sources AND source.node_type CONTAINS 'CALL'
  AND ($scoped = false OR source.file_path IN $changed_files)

MATCH (sink:CPGNode)
WHERE sink.function_name IN $sinks AND sink.node_type CONTAINS 'CALL'

CALL apoc.path.expandConfig(source, {
    relationshipFilter: "CALL>|REACHING_DEF>|REF>|ALIAS>",
    minLevel: 1,
    maxLevel: 30,
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
        base_fallback = """
MATCH path = (source:CPGNode)-[:CALL|REACHING_DEF|REF*1..15]->(sink:CPGNode)
WHERE source.function_name IN $sources AND source.node_type CONTAINS 'CALL'
  AND ($scoped = false OR source.file_path IN $changed_files)
  AND sink.function_name IN $sinks AND sink.node_type CONTAINS 'CALL'
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
        return base_apoc if self._check_apoc() else base_fallback

    def _bridge_opaque_binaries(self) -> None:
        """
        Injects REACHING_DEF edges into the graph for known library functions
        (like memcpy, std::copy) where the internal implementation is opaque
        but the data flow summary is known (arg1 -> arg0).
        """
        logger.info("TaintTracker: bridging opaque binaries with library summaries")
        with self.driver.session() as session:
            query = """
            MATCH (in_node:CPGNode)-[:REACHING_DEF|CALL]->(call:CPGNode)
            WHERE call.node_type CONTAINS 'CALL' AND (
                call.function_name IN ['memcpy', 'memmove', 'strcpy', 'strncpy',
                                       'std::copy', 'std::copy_n']
            )
            MATCH (call)-[:REACHING_DEF|CALL]->(out_node:CPGNode)
            WHERE NOT (in_node)-[:REACHING_DEF {summary: true}]->(out_node)
            WITH in_node, out_node
            LIMIT 500
            MERGE (in_node)-[:REACHING_DEF {summary: true}]->(out_node)
            RETURN count(*) AS bridges
            """
            try:
                result = session.run(query)
                record = result.single()
                bridges = record["bridges"] if record else 0
                logger.info("TaintTracker: created %d summary bridges", bridges)
            except Exception as e:
                logger.debug("TaintTracker: bridging opaque binaries failed: %s", e)

    def _resolve_virtual_calls(self) -> None:
        """
        Heuristic: Resolves virtual/indirect calls by linking CALL nodes to 
        concrete function implementations with matching names/parameters.
        """
        logger.info("TaintTracker: resolving virtual and indirect calls")
        with self.driver.session() as session:
            query = """
            MATCH (call:CPGNode)-[:CALL]->(abstract_target:CPGNode)
            WHERE call.node_type CONTAINS 'CALL' AND abstract_target.node_type = 'AST_FUNC'

            MATCH (concrete_impl:CPGNode)
            WHERE concrete_impl.node_type = 'AST_FUNC' 
              AND concrete_impl.function_name = abstract_target.function_name
              AND concrete_impl.node_id <> abstract_target.node_id

            MERGE (call)-[:CALL {resolved_virtual: true}]->(concrete_impl)
            RETURN count(*) AS resolutions
            """
            try:
                result = session.run(query)
                count = result.single()["resolutions"]
                if count > 0:
                    logger.info("TaintTracker: resolved %d virtual dispatch paths", count)
            except Exception as e:
                logger.debug("TaintTracker: virtual resolution failed: %s", e)

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
