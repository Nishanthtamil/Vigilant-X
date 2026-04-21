import time
import shutil
import os
import re
from pathlib import Path
from vigilant.models import VulnerabilityStatus
from vigilant.orchestrator import run_review
from vigilant.ingestion.cpg_builder import get_driver

ROOT_DIR = Path(__file__).parent.parent
BENCHMARK_REPO = ROOT_DIR / "benchmarks" / "mock_repo"
BENCHMARK_CODE_LAW = BENCHMARK_REPO / "code_law"

# Configure Neo4j to use the local test container on port 7688
os.environ["USE_LOCAL_NEO4J"] = "true"
os.environ["NEO4J_LOCAL_URI"] = "bolt://localhost:7688"
os.environ["NEO4J_LOCAL_PASSWORD"] = "vigilant_local"

def setup_benchmark_repo():
    """Ensure mock_repo exists with minimal structure."""
    BENCHMARK_REPO.mkdir(parents=True, exist_ok=True)
    BENCHMARK_CODE_LAW.mkdir(exist_ok=True)
    
    # Copy default rules
    default_rules = ROOT_DIR / "code_law" / "default_rules.yaml"
    if default_rules.exists():
        shutil.copy2(default_rules, BENCHMARK_CODE_LAW / "default_rules.yaml")

def _prewarm_cpg(support_files: list):
    """Build CPG for support library once. Results persist in Neo4j."""
    print(f"Pre-warming CPG with {len(support_files)} support files...")
    support_file_names = [f.name for f in support_files]
    run_review(
        repo_path=str(BENCHMARK_REPO.absolute()),
        pr_number=0,
        base_sha="main",
        head_sha="head",
        changed_files=support_file_names,
        dry_run=True,
    )

def run_juliet_benchmark(cwe_id: str = "CWE121", max_cases: int = 200, offset: int = 0) -> dict:
    juliet_path = ROOT_DIR / "benchmarks" / "juliet" / cwe_id
    support_path = ROOT_DIR / "benchmarks" / "juliet" / "support"
    
    if not juliet_path.exists():
        print(f"Juliet dataset for {cwe_id} not found at {juliet_path}")
        return {}

    bad_files  = sorted(juliet_path.glob("*_bad*.cpp"))[offset:offset+max_cases]
    good_files = sorted(juliet_path.glob("*_good*.cpp"))[offset:offset+max_cases]
    total_files = bad_files + good_files

    if not total_files:
        print(f"No test cases found in {juliet_path}")
        return {}

    setup_benchmark_repo()
    
    # Clear Neo4j entirely before pre-warming
    try:
        driver = get_driver()
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
    except Exception as e:
        print(f"Failed to clear Neo4j: {e}")

    # ── Step 1: Pre-warm with support library ──────────────────
    if support_path.exists():
        for f in support_path.glob("*"):
            shutil.copy2(f, BENCHMARK_REPO / f.name)
    
    support_files = list(BENCHMARK_REPO.glob("*.h")) + list(BENCHMARK_REPO.glob("*.c"))
    if support_files:
        try:
            _prewarm_cpg(support_files)
        except Exception as e:
            print(f"Support library pre-warm failed (non-fatal): {e}")

    # ── Step 2: Analyze each test file INCREMENTALLY ─────────────────────────
    tp = fp = tn = fn = 0
    start_time = time.time()

    for file_path in total_files:
        is_bad = "_bad" in file_path.name
        file_name = file_path.name
        print(f"\n--- Evaluating {file_name} ---")

        # Only delete nodes for THIS specific test case group to keep support library
        import re as _re
        base_prefix = _re.sub(r'(_bad|a|b|c|d|e|f|_good[A-Z0-9]+)\.cpp$', '', file_name)
        
        try:
            driver = get_driver()
            with driver.session() as session:
                # Delete nodes belonging to any file that starts with this prefix
                session.run(
                    "MATCH (n:CPGNode) WHERE n.file_path CONTAINS $prefix DETACH DELETE n",
                    prefix=base_prefix,
                )
        except Exception as e:
            print(f"Failed to clear file nodes: {e}")

        # Cleanup old test files from mock_repo (not support files)
        for f in BENCHMARK_REPO.glob("CWE*.*"):
            f.unlink()

        # Copy all related files for this case
        related_files = list(juliet_path.glob(f"{base_prefix}*"))
        for rf in related_files:
            shutil.copy2(rf, BENCHMARK_REPO / rf.name)

        # Analysis
        try:
            state = run_review(
                repo_path=str(BENCHMARK_REPO.absolute()),
                pr_number=0,
                base_sha="main",
                head_sha="head",
                changed_files=[file_name], 
                dry_run=True,
            )
            
            critical_vulns = [
                v for v in state.vulnerabilities
                if v.status in (
                    VulnerabilityStatus.SANDBOX_VERIFIED,
                    VulnerabilityStatus.FUZZ_VERIFIED,
                    VulnerabilityStatus.PROVEN,
                    VulnerabilityStatus.LIKELY,
                )
            ]
            has_bug = len(critical_vulns) > 0

            if is_bad:
                if has_bug:
                    print(f"[TP] correctly found bug")
                    tp += 1
                else:
                    print(f"[FN] missed bug")
                    fn += 1
            else:
                if has_bug:
                    print(f"[FP] false positive on clean code")
                    fp += 1
                else:
                    print(f"[TN] correctly found nothing")
                    tn += 1

        except Exception as e:
            print(f"Error: {e}")
            if is_bad: fn += 1
            else: fp += 1

    elapsed = time.time() - start_time
    # ... rest of metrics ...
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)
    
    print(f"\n{'='*50}\nJULIET {cwe_id} RESULTS\n{'='*50}")
    print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
    print(f"Precision: {precision:.3f}, Recall: {recall:.3f}, F1: {f1:.3f}")
    print(f"Total time: {elapsed:.1f}s ({elapsed/len(total_files):.1f}s/file)\n{'='*50}")
    
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

if __name__ == "__main__":
    import sys
    if "--juliet" in sys.argv:
        idx = sys.argv.index("--juliet")
        cwe = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "CWE121"
        max_n = int(sys.argv[idx + 2]) if idx + 2 < len(sys.argv) else 5
        run_juliet_benchmark(cwe, max_n)
    else:
        print("Usage: python scripts/evaluate_benchmark.py --juliet CWE_ID [max_cases]")
