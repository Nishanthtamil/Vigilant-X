"""
scripts/bench_bigvul.py
────────────────────────
Runs Vigilant-X against the BigVul dataset and prints precision/recall/F1.

Setup:
  1. Download BigVul from https://github.com/ZeoVan/MSR_20_Code_vulnerability_commits_Dataset
     and place the CSV at: benchmarks/bigvul/MSR_data_cleaned.csv
  2. Run: python scripts/bench_bigvul.py --split test --max 500 --lang C

The script:
  - Reads BigVul rows for the requested language and split.
  - For each "before" commit file → expects PROVEN/LIKELY/SANDBOX_VERIFIED/FUZZ_VERIFIED.
  - For each "after" commit file  → expects WARNING/ADVISORY (clean).
  - Computes TP/FP/TN/FN, then precision/recall/F1/FPR.
  - Writes results to benchmarks/results/bigvul_{date}.json.
"""
from __future__ import annotations
import argparse, csv, json, shutil, tempfile, time
from datetime import datetime
from pathlib import Path
import os

os.environ["USE_LOCAL_NEO4J"] = "true"
os.environ["NEO4J_LOCAL_URI"] = "bolt://localhost:7688"

ROOT = Path(__file__).parent.parent
BIGVUL_CSV = ROOT / "benchmarks" / "bigvul" / "MSR_data_cleaned.csv"
RESULTS_DIR = ROOT / "benchmarks" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

TP_STATUSES = {"PROVEN", "SANDBOX_VERIFIED", "FUZZ_VERIFIED", "LIKELY"}

def _reset_neo4j():
    try:
        from vigilant.ingestion.cpg_builder import get_driver
        with get_driver().session() as s:
            s.run("MATCH (n) DETACH DELETE n")
    except Exception as e:
        print(f"  [warn] neo4j reset failed: {e}")

def run_on_code(code: str, filename: str) -> str:
    """Write code to a temp dir and run Vigilant-X. Returns highest status string."""
    from vigilant.orchestrator import run_review
    from vigilant.models import VulnerabilityStatus
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / filename
        p.write_text(code)
        # Copy code_law rules
        cl_src = ROOT / "code_law"
        if cl_src.exists():
            shutil.copytree(cl_src, Path(tmp) / "code_law")
        state = run_review(
            repo_path=tmp, pr_number=0,
            base_sha="main", head_sha="head",
            changed_files=[filename], dry_run=True,
        )
    statuses = {v.status.value for v in state.vulnerabilities}
    if statuses & TP_STATUSES:
        return "POSITIVE"
    return "NEGATIVE"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max", type=int, default=200)
    parser.add_argument("--lang", default="C")
    args = parser.parse_args()

    if not BIGVUL_CSV.exists():
        print(f"BigVul CSV not found at {BIGVUL_CSV}")
        print("Download from: https://github.com/ZeoVan/MSR_20_Code_vulnerability_commits_Dataset")
        return

    rows = []
    with BIGVUL_CSV.open() as f:
        for row in csv.DictReader(f):
            if row.get("lang", "").strip() == args.lang:
                rows.append(row)
            if len(rows) >= args.max * 2:
                break

    before_rows = [r for r in rows if r.get("vul", "0") == "1"][:args.max]
    after_rows  = [r for r in rows if r.get("vul", "0") == "0"][:args.max]

    tp = fp = tn = fn = 0
    start = time.time()

    for r in before_rows:
        _reset_neo4j()
        result = run_on_code(r.get("func_before", ""), f"bigvul_{r['index']}.c")
        if result == "POSITIVE":
            tp += 1; print(f"[TP] {r['index']}")
        else:
            fn += 1; print(f"[FN] {r['index']}")

    for r in after_rows:
        _reset_neo4j()
        result = run_on_code(r.get("func_after", ""), f"bigvul_{r['index']}_fixed.c")
        if result == "NEGATIVE":
            tn += 1; print(f"[TN] {r['index']}")
        else:
            fp += 1; print(f"[FP] {r['index']}")

    elapsed = time.time() - start
    precision = tp/(tp+fp) if tp+fp else 0
    recall    = tp/(tp+fn) if tp+fn else 0
    f1        = 2*precision*recall/(precision+recall) if precision+recall else 0
    fpr       = fp/(fp+tn) if fp+tn else 0

    results = {
        "dataset": "BigVul", "lang": args.lang,
        "date": datetime.utcnow().isoformat(),
        "n_before": len(before_rows), "n_after": len(after_rows),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision,3), "recall": round(recall,3),
        "f1": round(f1,3), "fpr": round(fpr,3),
        "elapsed_s": round(elapsed,1),
    }
    print(json.dumps(results, indent=2))
    out = RESULTS_DIR / f"bigvul_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out}")

if __name__ == "__main__":
    main()
