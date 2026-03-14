"""
vigilant/models.py
───────────────────
Shared Pydantic v2 data models used across all four intelligence planes.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Plane I — Ingestion
# ─────────────────────────────────────────────────────────────────────────────


class PRContext(BaseModel):
    repo_path: str
    pr_number: int
    base_sha: str
    head_sha: str
    changed_files: list[str] = Field(default_factory=list)
    pr_title: str = ""
    pr_body: str = ""
    pr_author: str = ""
    github_repo: str = ""  # "owner/repo"


class PRIntent(BaseModel):
    purpose: str
    changed_modules: list[str] = Field(default_factory=list)
    risk_areas: list[str] = Field(default_factory=list)
    code_law_violations_suspected: list[str] = Field(default_factory=list)


class CPGNode(BaseModel):
    node_id: str
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    node_type: str           # "AST_FUNC", "CFG_BLOCK", "PDG_NODE"
    content_hash: str        # SHA-256 of function source — used for incremental updates
    properties: dict[str, Any] = Field(default_factory=dict)


class CPGSummary(BaseModel):
    nodes_created: int = 0
    nodes_updated: int = 0
    nodes_unchanged: int = 0
    edges_created: int = 0
    ingestion_mode: str = "full"  # "full" | "incremental"


# ─────────────────────────────────────────────────────────────────────────────
# Plane II — Analysis
# ─────────────────────────────────────────────────────────────────────────────


class TaintNode(BaseModel):
    """A single node in a source→sink taint path."""
    node_id: str
    file_path: str
    function_name: str
    line_number: int
    node_role: str    # "SOURCE" | "INTERMEDIATE" | "SINK"
    label: str        # e.g. "argv[1]" or "memcpy"


class TaintPath(BaseModel):
    path_id: str
    source: TaintNode
    sink: TaintNode
    intermediate_nodes: list[TaintNode] = Field(default_factory=list)
    crosses_files: bool = False
    rule_id: str = ""        # Code Law rule that triggered this path
    rule_severity: str = ""  # "CRITICAL" | "ADVISORY"

    @property
    def full_path(self) -> list[TaintNode]:
        return [self.source, *self.intermediate_nodes, self.sink]


class VulnerabilityStatus(str, Enum):
    PROVEN = "PROVEN"               # Z3 found a satisfying witness
    FUZZ_VERIFIED = "FUZZ_VERIFIED" # LibFuzzer found a crash (Z3 returned unknown)
    SANDBOX_VERIFIED = "SANDBOX_VERIFIED"  # ASan/TSan/MSan crash confirmed
    WARNING = "WARNING"             # Suspicious path, sandbox passed (no crash)
    ADVISORY = "ADVISORY"           # ADVISORY severity rule — no sandbox
    FALSE_POSITIVE = "FALSE_POSITIVE"


class WitnessValue(BaseModel):
    variable: str
    value: str
    explanation: str = ""


class Vulnerability(BaseModel):
    vuln_id: str
    taint_path: TaintPath
    status: VulnerabilityStatus = VulnerabilityStatus.WARNING
    z3_formula: str = ""
    witness_values: list[WitnessValue] = Field(default_factory=list)
    z3_proof: str = ""
    fuzz_crash_input: str = ""
    confidence: float = 0.0    # 0.0–1.0
    summary: str = ""           # Short human-readable headline


# ─────────────────────────────────────────────────────────────────────────────
# Plane III — Validation
# ─────────────────────────────────────────────────────────────────────────────


class PoCFile(BaseModel):
    file_name: str = "repro.cpp"
    content: str
    mocking_framework: str = ""  # "googlemock" | "fakeit" | "hippomocks" | ""
    build_flags: str = ""


class SandboxResult(BaseModel):
    passed: bool                  # True = no crash (downgrade to WARNING)
    crash_type: str = ""          # "heap-buffer-overflow", "use-after-free", etc.
    sanitizer: str = ""           # "ASan", "TSan", "MSan", "UBSan"
    stack_trace: str = ""
    raw_output: str = ""
    compilation_error: str = ""   # Non-empty if compile step failed
    compiler_override_used: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Plane IV — Communication
# ─────────────────────────────────────────────────────────────────────────────


class Fix(BaseModel):
    description: str
    diff: str         # unified diff format
    cpp_standard: str = "C++20"   # C++17 | C++20 | C++23
    fix_sandbox_result: SandboxResult | None = None  # Sandbox run of the fix itself


class ReviewReport(BaseModel):
    pr_number: int
    github_repo: str
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    fixes: dict[str, Fix] = Field(default_factory=dict)   # keyed by vuln_id
    advisory_comments: list[str] = Field(default_factory=list)
    markdown_body: str = ""
    posted_comment_url: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator Agent State (LangGraph)
# ─────────────────────────────────────────────────────────────────────────────


class AgentState(BaseModel):
    """Mutable state object passed through the LangGraph pipeline."""
    model_config = {"arbitrary_types_allowed": True}

    pr_context: PRContext | None = None

    pr_intent: PRIntent | None = None
    cpg_summary: CPGSummary | None = None
    taint_paths: list[TaintPath] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    poc_files: dict[str, PoCFile] = Field(default_factory=dict)   # keyed by vuln_id
    sandbox_results: dict[str, SandboxResult] = Field(default_factory=dict)
    review_report: ReviewReport | None = None
    errors: list[str] = Field(default_factory=list)
    dry_run: bool = False
