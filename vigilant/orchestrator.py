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


from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time


class _RateLimiter:
    """Token-bucket rate limiter for LLM API calls."""
    def __init__(self, rps: float):
        self._interval = 1.0 / rps
        self._last = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


_LLM_RATE_LIMITER = _RateLimiter(rps=0.15)  # 9 RPM sustained - extremely safe for 90k TPM budget


class DeepScanBudget:
    """
    Controls Deep Scan concurrency and total file budget per PR run.
    """

    MAX_FILES_PER_RUN   = 40    # absolute ceiling across all files
    MAX_CONCURRENT      = 1     # Serial execution to avoid token-burst 429s
    HIGH_PRIORITY_EXTS  = {".cpp", ".cc", ".c", ".py", ".ts", ".js"}

    def __init__(self) -> None:
        self._sem = threading.Semaphore(self.MAX_CONCURRENT)

    def prioritize(
        self,
        scan_args: list[tuple],          # (f_rel, f_path, rules)
        changed_files: list[str],
    ) -> list[tuple]:
        """Sort scan_args by priority and cap at MAX_FILES_PER_RUN."""
        changed_set = set(changed_files)

        def _score(arg: tuple) -> float:
            f_rel, f_path, rules = arg
            score = 0.0
            # In-PR files are highest priority
            if f_rel in changed_set:
                score += 10.0
            # File extension signals — compiled languages > scripts
            ext = Path(f_rel).suffix
            if ext in (".cpp", ".cc", ".c"):
                score += 3.0
            elif ext in (".py", ".ts", ".js"):
                score += 2.0
            # More critical rules = more likely to find something
            critical_count = sum(1 for r in rules if r.severity.value == "CRITICAL")
            score += critical_count * 0.5
            return score

        ranked = sorted(scan_args, key=_score, reverse=True)
        capped  = ranked[:self.MAX_FILES_PER_RUN]

        if len(scan_args) > self.MAX_FILES_PER_RUN:
            logger.info(
                "DeepScanBudget: %d files eligible, capped at %d "
                "(top priority: %s)",
                len(scan_args), self.MAX_FILES_PER_RUN,
                [a[0] for a in capped[:5]],
            )

        return capped

    def run_with_budget(
        self,
        scan_args: list[tuple],
        runner_fn,                        # callable(args) -> list[Vulnerability]
        changed_files: list[str],
    ) -> list:
        """Execute runner_fn for each arg under semaphore and budget controls."""
        prioritized = self.prioritize(scan_args, changed_files)
        results: list = []

        def _run(args):
            _LLM_RATE_LIMITER.acquire()
            with self._sem:
                return runner_fn(args)

        with ThreadPoolExecutor(max_workers=self.MAX_CONCURRENT) as pool:
            futures = {pool.submit(_run, args): args[0] for args in prioritized}
            for fut in as_completed(futures):
                try:
                    results.append((futures[fut], fut.result()))
                except Exception as exc:
                    logger.error("[Analysis] Deep scan failed for %s: %s", futures[fut], exc)

        return results


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
    """Plane II — Taint tracking + concolic analysis + Parallel Deep Scan."""
    agent = AgentState(**state)
    ctx = agent.pr_context
    repo_path = Path(ctx.repo_path) if ctx else None

    try:
        # ── Phase 1: Graph-based taint analysis ─────────────────────────────
        logger.info("[Analysis] Running taint tracker")
        code_law = CodeLaw(repo_path=repo_path)
        tracker = TaintTracker(code_law=code_law, repo_path=repo_path)
        paths = tracker.find_taint_paths(
            pr_intent=agent.pr_intent,
            changed_files=ctx.changed_files if ctx else None
        )
        logger.info("[Analysis] Found %d taint paths", len(paths))

        logger.info("[Analysis] Running concolic engine")
        engine = ConcolicEngine()
        graph_vulns = engine.analyze(paths)

        # ── Phase 2: LLM Deep Scan — ALWAYS runs, independent of Phase 1 ───
        # Phase 1 finds cross-file flow. Phase 2 finds local patterns.
        # Both are needed. Neither is a fallback for the other.
        deep_scan_vulns = []
        if ctx:
            files_to_scan = (
                ctx.changed_files
                if ctx.changed_files
                else [
                    str(f.relative_to(repo_path))
                    for f in repo_path.glob("**/*")
                    if f.is_file() and f.suffix in (".cpp", ".cc", ".c", ".h", ".hpp", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs")
                ]
            )

            scan_args = []
            for f_rel in files_to_scan:
                f_path = repo_path / f_rel
                if not f_path.exists():
                    continue
                matching_rules = code_law.rules_for_file(f_rel)
                if matching_rules:
                    scan_args.append((f_rel, f_path, matching_rules))

            if scan_args:
                logger.info("[Analysis] Launching Deep Scan for %d files (budget-controlled)", len(scan_args))
                budget = DeepScanBudget()
                scan_results = budget.run_with_budget(
                    scan_args=scan_args,
                    runner_fn=lambda args: engine.deep_scan(
                        args[1], args[2], repo_path=repo_path
                    ),
                    changed_files=ctx.changed_files or [],
                )
                for f_rel, findings in scan_results:
                    deep_scan_vulns.extend(findings)

        # ── Phase 3: Merge and deduplicate ──────────────────────────────────
        # Graph vulns are higher confidence — they have Z3 proofs and paths.
        # Deep scan vulns fill in what the graph missed.
        # Deduplicate by (file, line, sink_name) to avoid double-reporting.
        all_vulns = list(graph_vulns)
        
        graph_keys = {
            (v.taint_path.sink.file_path, 
             v.taint_path.sink.line_number,
             v.taint_path.sink.function_name)
            for v in graph_vulns
        }
        
        logger.info("[Analysis] Merging %d graph findings and %d deep scan findings", len(graph_vulns), len(deep_scan_vulns))

        for v in deep_scan_vulns:
            key = (
                v.taint_path.sink.file_path,
                v.taint_path.sink.line_number,
                v.taint_path.sink.function_name,
            )
            # Add deep scan finding only if graph analysis didn't already cover it
            # OR if graph found it too, upgrade the confidence
            if key not in graph_keys:
                _DEEP_SCAN_MIN_CONFIDENCE = 0.70
                if v.confidence >= _DEEP_SCAN_MIN_CONFIDENCE:
                    logger.info("[Analysis] Keeping deep scan finding: %s at %d (conf: %.2f)", v.vuln_id[:8], v.taint_path.sink.line_number, v.confidence)
                    all_vulns.append(v)
                else:
                    logger.info("[Analysis] Dropping deep scan finding: %s (conf: %.2f < %.2f)", v.vuln_id[:8], v.confidence, _DEEP_SCAN_MIN_CONFIDENCE)
            else:
                # Graph already found this — boost confidence if deep scan agrees
                for i, gv in enumerate(all_vulns):
                    gkey = (
                        gv.taint_path.sink.file_path,
                        gv.taint_path.sink.line_number,
                        gv.taint_path.sink.function_name,
                    )
                    if gkey == key:
                        boosted = min(gv.confidence + 0.10, 0.99)
                        logger.info("[Analysis] Boosting graph finding %s confidence: %.2f -> %.2f", gv.vuln_id[:8], gv.confidence, boosted)
                        all_vulns[i] = gv.model_copy(
                            update={"confidence": boosted}
                        )
                        break

        # FP filter and context scoring applied to merged results
        from vigilant.fp_filter import apply_fp_filter
        all_vulns, fp_dropped = apply_fp_filter(all_vulns, repo_path=repo_path)
        if fp_dropped:
            logger.info("[Analysis] FP filter dropped %d findings", len(fp_dropped))

        from vigilant.analysis.context_scorer import ContextScorer
        scorer = ContextScorer(repo_path=repo_path)
        for i, v in enumerate(all_vulns):
            if v.status in (VulnerabilityStatus.PROVEN, VulnerabilityStatus.LIKELY):
                new_conf = scorer.score(v)
                if new_conf < 0.60:
                    all_vulns[i] = v.model_copy(update={
                        "status": VulnerabilityStatus.WARNING,
                        "confidence": new_conf,
                    })
                elif new_conf < 0.80 and v.status == VulnerabilityStatus.PROVEN:
                    all_vulns[i] = v.model_copy(update={
                        "status": VulnerabilityStatus.LIKELY,
                        "confidence": new_conf,
                    })

        from vigilant.analysis.nitpick_engine import NitpickEngine
        # Only nitpick files with no PROVEN/LIKELY findings
        files_with_findings = {v.taint_path.sink.file_path for v in all_vulns
                               if v.status.value in ("PROVEN","LIKELY","SANDBOX_VERIFIED","FUZZ_VERIFIED")}
        nitpick_engine = NitpickEngine()
        for f_rel in (ctx.changed_files or [])[:20]:
            if f_rel in files_with_findings:
                continue
            f_path = repo_path / f_rel
            if f_path.exists() and f_path.stat().st_size < 50_000:
                all_vulns.extend(nitpick_engine.analyze_file(f_path, repo_path=repo_path))

        agent.taint_paths = paths
        agent.vulnerabilities = all_vulns

        proven = sum(1 for v in all_vulns if v.status == VulnerabilityStatus.PROVEN)
        fuzz = sum(1 for v in all_vulns if v.status == VulnerabilityStatus.FUZZ_VERIFIED)
        advisory = sum(1 for v in all_vulns if v.status == VulnerabilityStatus.ADVISORY)
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

    updated_vulns = []
    for vuln in agent.vulnerabilities:
        # Skip ADVISORY — no PoC or sandbox needed
        if vuln.status == VulnerabilityStatus.ADVISORY:
            updated_vulns.append(vuln)
            continue

        try:
            logger.info("[Validation] Generating PoC for %s", vuln.vuln_id[:8])
            poc = poc_gen.generate(vuln)
            agent.poc_files[vuln.vuln_id] = poc

            # Skip sandbox for non-C++ findings — the PoC is a stub
            if poc.content.startswith("// SKIP:"):
                updated_vulns.append(vuln)  # preserve LIKELY status as-is
                continue

            if not agent.dry_run or settings.sandbox_always_run:
                logger.info("[Validation] Running sandbox for %s", vuln.vuln_id[:8])
                
                ext = Path(vuln.taint_path.sink.file_path).suffix.lower()
                if ext == ".py":
                    from vigilant.validation.sandbox_runner_py import PythonSandboxRunner
                    sandbox_inst = PythonSandboxRunner(repo_path=repo_path)
                elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
                    from vigilant.validation.sandbox_runner_js import JSSandboxRunner
                    sandbox_inst = JSSandboxRunner(repo_path=repo_path)
                elif ext == ".go":
                    from vigilant.validation.sandbox_runner_go import GoSandboxRunner
                    sandbox_inst = GoSandboxRunner(repo_path=repo_path)
                else:
                    sandbox_inst = sandbox # Default C++ sandbox

                # Capture sanitizer type before running so we can assess correctness
                sanitizer_type = ""
                if hasattr(sandbox_inst, "_infer_sanitizer"):
                     sanitizer_type = sandbox_inst._infer_sanitizer(vuln)
                
                result = sandbox_inst.run(vuln, poc)
                agent.sandbox_results[vuln.vuln_id] = result

                if not result.passed and not result.compilation_error:
                    # Confirmed crash — upgrade to SANDBOX_VERIFIED
                    vuln = vuln.model_copy(update={"status": VulnerabilityStatus.SANDBOX_VERIFIED})
                    logger.info("[Validation] Sandbox CRASH confirmed: %s", result.crash_type)

                elif result.passed:
                    # Sandbox passed.
                    ran_correct_sanitizer = not (
                        getattr(vuln, "requires_msan", False)
                        and sanitizer_type not in ("memory",)
                    )
                    if ran_correct_sanitizer:
                        old_status = vuln.status
                        # If sandbox passed with correct sanitizer, it's a false positive or not exploitable.
                        # Downgrade to WARNING (to distinguish from Verified)
                        vuln = vuln.model_copy(update={"status": VulnerabilityStatus.WARNING})
                        logger.info(
                            "[Validation] Sandbox PASSED with correct sanitizer. "
                            "Downgrading %s: %s → WARNING",
                            vuln.vuln_id[:8], old_status,
                        )
                    else:
                        # Wrong sanitizer for this vuln class — preserve PROVEN
                        logger.info(
                            "[Validation] Sandbox PASSED but wrong sanitizer (%s) "
                            "for MSan-class vuln %s — preserving %s status",
                            sanitizer_type, vuln.vuln_id[:8], vuln.status,
                        )
                elif result.compilation_error:
                    # PoC couldn't compile — infrastructure issue, not proof of safety.
                    # Keep as is or downgrade PROVEN to LIKELY.
                    if vuln.status == VulnerabilityStatus.PROVEN:
                        vuln = vuln.model_copy(update={"status": VulnerabilityStatus.LIKELY})
                        logger.info(
                            "[Validation] PoC compile error for %s — "
                            "downgrading PROVEN → LIKELY (infrastructure issue)",
                            vuln.vuln_id[:8],
                        )
                    else:
                        # already LIKELY or similar
                        pass
            else:
                logger.info("[Validation] dry-run: skipping sandbox for %s", vuln.vuln_id[:8])

        except Exception as e:
            agent.errors.append(f"Validation error for {vuln.vuln_id[:8]}: {e}")
            logger.error("[Validation] Error: %s", e)
        
        updated_vulns.append(vuln)

    agent.vulnerabilities = updated_vulns

    return agent.model_dump()


def node_communicate(state: dict[str, Any]) -> dict[str, Any]:
    """Plane IV — Generate report and post to PR."""
    agent = AgentState(**state)
    ctx = agent.pr_context
    if ctx is None:
        return agent.model_dump()

    try:
        repo_path = Path(ctx.repo_path)
        from vigilant.suppression import load_suppressions, apply_suppressions
        suppressions = load_suppressions(repo_path)
        agent.vulnerabilities = apply_suppressions(agent.vulnerabilities, suppressions)

        sandbox = SandboxRunner(repo_path=repo_path) if not agent.dry_run else None
        reviewer = Reviewer(sandbox_runner=sandbox)
        report = reviewer.generate_report(
            pr_number=ctx.pr_number,
            github_repo=ctx.github_repo,
            head_sha=ctx.head_sha,
            vulnerabilities=agent.vulnerabilities,
            sandbox_results=agent.sandbox_results,
            poc_files=agent.poc_files,
            repo_path=repo_path,
            pr_intent=agent.pr_intent,
            changed_files=ctx.changed_files,
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
