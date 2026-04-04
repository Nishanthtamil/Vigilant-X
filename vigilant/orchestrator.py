"""
vigilant/orchestrator.py
─────────────────────────
LangGraph state machine wiring all four intelligence planes together.

Graph:
  [ingest] → [analyze] → [validate] → [communicate]

Each node receives the AgentState, performs its work, and returns an updated state.
Errors are collected non-fatally so partial results can still be reported.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph

from vigilant.config import CodeLaw, get_settings
from vigilant.ingestion.cpg_builder import CPGBuilder
from vigilant.ingestion.intent_parser import IntentParser
from vigilant.analysis.taint_tracker import TaintTracker
from vigilant.analysis.concolic_engine import ConcolicEngine
from vigilant.communication.pr_commenter import PRCommenter
from vigilant.communication.reviewer import Reviewer
from vigilant.llm_client import LLMClient
from vigilant.models import AgentState, PRContext, VulnerabilityStatus
from vigilant.validation.poc_generator import PoCGenerator
from vigilant.validation.sandbox_runner import SandboxRunner

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Node functions (each mutates a copy of AgentState)
# ─────────────────────────────────────────────────────────────────────────────


def node_ingest(state: dict[str, Any]) -> dict[str, Any]:
    """Plane I — Build/update CPG and parse PR intent."""
    agent = AgentState(**state)
    ctx = agent.pr_context
    if ctx is None:
        agent.errors.append("Ingestion: no PRContext provided")
        return agent.model_dump()

    repo_path = Path(ctx.repo_path)

    try:
        logger.info("[Ingestion] Building CPG for %s", repo_path)
        builder = CPGBuilder()
        cpg_summary = builder.build_cpg(
            repo_path=repo_path,
            changed_files=ctx.changed_files,
            base_commit=ctx.base_sha,
        )
        agent.cpg_summary = cpg_summary
        logger.info("[Ingestion] CPG: %s", cpg_summary.model_dump())
    except Exception as e:
        agent.errors.append(f"CPG build error: {e}")
        logger.error("[Ingestion] CPG error: %s", e)

    try:
        logger.info("[Ingestion] Parsing PR intent")
        parser = IntentParser()
        readme = repo_path / "README.md"
        agent.pr_intent = parser.parse(ctx, readme_path=readme if readme.exists() else None)
        logger.info("[Ingestion] Intent: %s", agent.pr_intent.purpose[:80])
    except Exception as e:
        agent.errors.append(f"Intent parsing error: {e}")
        logger.error("[Ingestion] Intent error: %s", e)

    return agent.model_dump()


def node_analyze(state: dict[str, Any]) -> dict[str, Any]:
    """Plane II — Taint tracking + concolic analysis + Deep Scan fallback."""
    agent = AgentState(**state)
    ctx = agent.pr_context
    repo_path = Path(ctx.repo_path) if ctx else None

    try:
        logger.info("[Analysis] Running taint tracker")
        code_law = CodeLaw(repo_path=repo_path)
        tracker = TaintTracker(code_law=code_law)
        paths = tracker.find_taint_paths(pr_intent=agent.pr_intent)
        logger.info("[Analysis] Found %d taint paths", len(paths))

        logger.info("[Analysis] Running concolic engine")
        engine = ConcolicEngine()
        vulns = engine.analyze(paths)

        # ── Deep Scan Fallback ────────────────────────────────────────────────
        # If no vulnerabilities found, or for files matching specific rules,
        # perform a direct LLM-powered review of the file content.
        if ctx:
            # Identify files that ALREADY have vulnerabilities from taint tracking
            files_with_vulns = {v.taint_path.sink.file_path for v in vulns}
            
            files_to_scan = ctx.changed_files if ctx.changed_files else [str(f.relative_to(repo_path)) for f in repo_path.glob("**/*") if f.is_file() and f.suffix in (".cpp", ".cc", ".c", ".h", ".hpp")]
            logger.info("[Analysis] Files for Deep Scan: %s", files_to_scan)
            
            for f_rel in files_to_scan:
                # SKIP Deep Scan if we already found a vulnerability in this file via taint tracking
                if f_rel in files_with_vulns:
                    logger.info("[Analysis] Skipping Deep Scan for %s (already has findings)", f_rel)
                    continue

                f_path = repo_path / f_rel
                if not f_path.exists():
                    logger.warning("[Analysis] Deep Scan: file not found %s", f_path)
                    continue
                
                matching_rules = code_law.rules_for_file(f_rel)
                logger.info("[Analysis] File: %s | Matching Rules: %d", f_rel, len(matching_rules))
                if matching_rules:
                    deep_findings = engine.deep_scan(f_path, matching_rules)
                    logger.info("[Analysis] Deep Scan found %d findings for %s", len(deep_findings), f_rel)
                    vulns.extend(deep_findings)

        agent.taint_paths = paths
        agent.vulnerabilities = vulns

        proven = sum(1 for v in vulns if v.status == VulnerabilityStatus.PROVEN)
        fuzz = sum(1 for v in vulns if v.status == VulnerabilityStatus.FUZZ_VERIFIED)
        advisory = sum(1 for v in vulns if v.status == VulnerabilityStatus.ADVISORY)
        logger.info("[Analysis] Proven=%d FuzzVerified=%d Advisory=%d", proven, fuzz, advisory)

    except Exception as e:
        agent.errors.append(f"Analysis error: {e}")
        logger.error("[Analysis] Error: %s", e)

    return agent.model_dump()


def node_validate(state: dict[str, Any]) -> dict[str, Any]:
    """Plane III — PoC generation + sandbox execution."""
    agent = AgentState(**state)
    ctx = agent.pr_context
    if ctx is None:
        return agent.model_dump()

    repo_path = Path(ctx.repo_path)
    poc_gen = PoCGenerator(repo_path=repo_path)
    sandbox = SandboxRunner(repo_path=repo_path)

    settings = get_settings()

    for vuln in agent.vulnerabilities:
        # Skip ADVISORY — no PoC or sandbox needed
        if vuln.status == VulnerabilityStatus.ADVISORY:
            continue

        try:
            logger.info("[Validation] Generating PoC for %s", vuln.vuln_id[:8])
            poc = poc_gen.generate(vuln)
            agent.poc_files[vuln.vuln_id] = poc

            if not agent.dry_run or settings.sandbox_always_run:
                logger.info("[Validation] Running sandbox for %s", vuln.vuln_id[:8])
                result = sandbox.run(vuln, poc)
                agent.sandbox_results[vuln.vuln_id] = result

                # ── Sandbox Tie-Breaker ───────────────────────────────────────
                # If sandbox confirmed a crash, upgrade status
                if not result.passed and not result.compilation_error:
                    vuln.status = VulnerabilityStatus.SANDBOX_VERIFIED
                    logger.info("[Validation] Sandbox CRASH confirmed: %s", result.crash_type)
                elif result.passed:
                    # If sandbox passed (no crash), it's a False Positive or unexploitable
                    # Downgrade from PROVEN/FUZZ_VERIFIED to WARNING
                    old_status = vuln.status
                    vuln.status = VulnerabilityStatus.WARNING
                    logger.info(
                        "[Validation] Sandbox PASSED (no crash). Downgrading %s: %s → WARNING",
                        vuln.vuln_id[:8], old_status
                    )
                elif result.compilation_error:
                    logger.warning("[Validation] Sandbox compile error for %s", vuln.vuln_id[:8])
            else:
                logger.info("[Validation] dry-run: skipping sandbox for %s", vuln.vuln_id[:8])

        except Exception as e:
            agent.errors.append(f"Validation error for {vuln.vuln_id[:8]}: {e}")
            logger.error("[Validation] Error: %s", e)

    return agent.model_dump()


def node_communicate(state: dict[str, Any]) -> dict[str, Any]:
    """Plane IV — Generate report and post to PR."""
    agent = AgentState(**state)
    ctx = agent.pr_context
    if ctx is None:
        return agent.model_dump()

    try:
        repo_path = Path(ctx.repo_path)
        sandbox = SandboxRunner(repo_path=repo_path) if not agent.dry_run else None
        reviewer = Reviewer(sandbox_runner=sandbox)
        report = reviewer.generate_report(
            pr_number=ctx.pr_number,
            github_repo=ctx.github_repo,
            vulnerabilities=agent.vulnerabilities,
            sandbox_results=agent.sandbox_results,
            poc_files=agent.poc_files,
        )

        commenter = PRCommenter()
        report = commenter.post(report, dry_run=agent.dry_run)
        agent.review_report = report
        logger.info("[Communication] Report posted: %s", report.posted_comment_url)

        # Write SARIF output
        from vigilant.communication.sarif_writer import write_sarif
        sarif_out = Path(ctx.repo_path) / "vigilant-results.sarif"
        write_sarif(agent, sarif_out)
        logger.info("[Communication] SARIF written to %s", sarif_out)

    except Exception as e:
        agent.errors.append(f"Communication error: {e}")
        logger.error("[Communication] Error: %s", e)

    return agent.model_dump()


# ─────────────────────────────────────────────────────────────────────────────
# Graph construction
# ─────────────────────────────────────────────────────────────────────────────


def build_graph() -> Any:
    """Construct and compile the LangGraph pipeline."""
    graph = StateGraph(dict)

    graph.add_node("ingest", node_ingest)
    graph.add_node("analyze", node_analyze)
    graph.add_node("validate", node_validate)
    graph.add_node("communicate", node_communicate)

    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "analyze")
    graph.add_edge("analyze", "validate")
    graph.add_edge("validate", "communicate")
    graph.add_edge("communicate", END)

    return graph.compile()


# ─────────────────────────────────────────────────────────────────────────────
# Public run function
# ─────────────────────────────────────────────────────────────────────────────


def run_review(
    repo_path: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    github_repo: str = "",
    pr_title: str = "",
    pr_body: str = "",
    dry_run: bool = False,
) -> AgentState:
    """
    Execute the full Vigilant-X review pipeline.

    Returns the final AgentState with vulnerabilities and report.
    """
    import logging
    logging.basicConfig(
        level=get_settings().log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    initial_state = AgentState(
        pr_context=PRContext(
            repo_path=repo_path,
            pr_number=pr_number,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            pr_title=pr_title,
            pr_body=pr_body,
            github_repo=github_repo,
        ),
        dry_run=dry_run,
    ).model_dump()

    graph = build_graph()
    try:
        final = graph.invoke(initial_state)
        return AgentState(**final)
    finally:
        from vigilant.ingestion.cpg_builder import close_driver
        close_driver()
