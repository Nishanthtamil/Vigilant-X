# vigilant/fp_filter.py
"""
False-positive filter: drops or demotes PROVEN/LIKELY findings where the
taint path passes through a framework-safe pattern.

Called in node_analyze() after ConcolicEngine.analyze(), before validation.
"""
from __future__ import annotations
import logging
import yaml
from pathlib import Path
from vigilant.models import Vulnerability, VulnerabilityStatus
from vigilant.ingestion.framework_detector import FrameworkDetector, FRAMEWORK_PROFILES

logger = logging.getLogger(__name__)

# Hard-coded global safe patterns that apply regardless of framework.
# These are stdlib / language primitives that cannot produce injection.
GLOBAL_SAFE_SINKS = {
    # C++ safe stdlib
    "std::vector::push_back", "std::string::append", "std::copy_n",
    "std::min", "std::max", "std::clamp",
    # Python safe ORM
    "filter", "exclude", "get", "create", "update_or_create",
    "values", "values_list", "annotate", "aggregate",
    # JS safe patterns
    "JSON.stringify", "encodeURIComponent", "escape",
    "res.json", "res.status", "res.sendStatus",
}

def _load_yaml_safe_patterns() -> set[str]:
    """Load additional safe patterns from vigilant/fp_safe_patterns.yaml."""
    extra_safe = set()
    yaml_path = Path(__file__).parent / "fp_safe_patterns.yaml"
    if yaml_path.exists():
        try:
            with yaml_path.open() as f:
                data = yaml.safe_load(f)
            if data:
                for framework in data:
                    patterns = data[framework]
                    if isinstance(patterns, list):
                        extra_safe.update(patterns)
        except Exception as e:
            logger.warning("FP filter: failed to load %s: %s", yaml_path, e)
    return extra_safe

def build_safe_set(repo_path: Path | None) -> set[str]:
    """Return union of global + YAML + framework-detected safe patterns."""
    safe = set(GLOBAL_SAFE_SINKS)
    safe.update(_load_yaml_safe_patterns())
    if repo_path:
        fd = FrameworkDetector(repo_path)
        for fw in fd.detect():
            profile = FRAMEWORK_PROFILES.get(fw, {})
            safe.update(profile.get("safe_patterns", []))
    return safe

import re as _re

# Patterns that indicate a dangerous call is already guarded
_BOUNDS_CHECK_RE = _re.compile(
    r'if\s*\([^)]*(?:len|size|length|sizeof|strlen|count|n)\s*[<>=!]=?\s*\d',
    _re.IGNORECASE,
)
_DANGEROUS_GUARDED_SINKS = {"memcpy", "memmove", "strncpy", "memset"}

def _has_local_bounds_check(vuln: Vulnerability, repo_path=None) -> bool:
    """
    Return True if the sink call is visibly inside a bounds-checked block.
    Reads ±10 lines around the sink line. Fast pre-filter before LLM.
    """
    if vuln.taint_path.sink.function_name not in _DANGEROUS_GUARDED_SINKS:
        return False
    if not repo_path:
        return False
    try:
        p = Path(repo_path) / vuln.taint_path.sink.file_path
        if not p.exists():
            return False
        lines = p.read_text(errors="replace").splitlines()
        line = vuln.taint_path.sink.line_number
        # Look at 10 lines before the sink for an if(...size...) guard
        window = "\n".join(lines[max(0, line - 10): line + 2])
        return bool(_BOUNDS_CHECK_RE.search(window))
    except Exception:
        return False

def apply_fp_filter(
    vulns: list[Vulnerability],
    repo_path: Path | None = None,
) -> tuple[list[Vulnerability], list[Vulnerability]]:
    """
    Returns (kept, dropped).
    
    Drop rules:
    1. Sink function is in safe_set → drop entirely.
    2. Any intermediate node function is in safe_set AND sink is not
       a high-confidence critical sink → demote PROVEN→LIKELY.
    3. Source and sink are the same node AND path length == 1 (stub CPG
       artifact) → drop as likely false positive.
    4. Sink is inside a visible bounds-checked block → demote to WARNING.
    """
    safe = build_safe_set(repo_path)
    HIGH_CONFIDENCE_SINKS = {
        "memcpy", "strcpy", "free", "system", "exec", "execve",
        "sprintf", "gets", "strcat", "pickle.loads", "yaml.load",
        "eval", "child_process.exec", "Marshal.load",
    }
    kept, dropped = [], []
    for v in vulns:
        p = v.taint_path
        sink_name = p.sink.function_name

        # Rule 1: sink is explicitly safe
        if sink_name in safe:
            logger.info("FP filter: dropping %s — sink %s is in safe set", v.vuln_id[:8], sink_name)
            dropped.append(v)
            continue

        # Rule 2: path routes through a safe intermediate
        intermediates = {n.function_name for n in p.intermediate_nodes}
        if intermediates & safe and sink_name not in HIGH_CONFIDENCE_SINKS:
            if v.status == VulnerabilityStatus.PROVEN:
                v = v.model_copy(update={"status": VulnerabilityStatus.LIKELY,
                                         "confidence": min(v.confidence, 0.72)})
                logger.info("FP filter: demoting %s PROVEN→LIKELY (safe intermediate)", v.vuln_id[:8])

        # Rule 3: trivial self-loop (stub CPG artifact)
        if p.source.node_id == p.sink.node_id and not p.intermediate_nodes:
            # EXEMPT: Deep Scan findings (LLM-only) naturally have same source/sink
            if p.sink.function_name == "DeepScan":
                kept.append(v)
                continue
                
            logger.info("FP filter: dropping %s — self-loop stub artifact", v.vuln_id[:8])
            dropped.append(v)
            continue

        # Rule 4: sink is inside a visible bounds-checked block → demote to WARNING
        if _has_local_bounds_check(v, repo_path) and v.status == VulnerabilityStatus.PROVEN:
            v = v.model_copy(update={
                "status": VulnerabilityStatus.WARNING,
                "confidence": min(v.confidence, 0.55),
            })
            logger.info("FP filter: demoting %s PROVEN→WARNING (local bounds check)", v.vuln_id[:8])

        kept.append(v)

    logger.info("FP filter: kept=%d dropped=%d", len(kept), len(dropped))
    return kept, dropped
