"""
scripts/bench_cvefixes.py
──────────────────────────
Benchmarks Vigilant-X on the CVEfixes dataset.

Setup:
  1. Clone https://github.com/secureIT-project/CVEfixes
  2. Run: python CVEfixes/code/collect_projects.py to generate the SQLite DB.
  3. Set CVEFIXES_DB env var to the path of CVEfixes.db.
  4. Run: python scripts/bench_cvefixes.py --lang python --max 200

Schema used:
  - table: file_change (filename, code_before, code_after, programming_language)
  - label: code_before = vulnerable (TP expected), code_after = fixed (TN expected)
"""
from __future__ import annotations
import argparse, json, os, shutil, sqlite3, tempfile, time
from datetime import datetime
from pathlib import Path

os.environ["USE_LOCAL_NEO4J"] = "true"
os.environ["NEO4J_LOCAL_URI"] = "bolt://localhost:7688"

ROOT = Path(__file__).parent.parent
RESULTS_DIR = ROOT / "benchmarks" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

TP_STATUSES = {"PROVEN", "SANDBOX_VERIFIED", "FUZZ_VERIFIED", "LIKELY"}

LANG_EXT = {
    "python": ".py", "javascript": ".js", "typescript": ".ts",
    "go": ".go", "java": ".java", "ruby": ".rb", "c": ".c", "c++": ".cpp",
}

def _reset_neo4j():
    try:
        from vigilant.ingestion.cpg_builder import get_driver
        with get_driver().session() as s:
            s.run("MATCH (n) DETACH DELETE n")
    except Exception:
        pass

def run_on_code(code: str, fname: str) -> str:
    from vigilant.orchestrator import run_review
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / fname).write_text(code, errors="replace")
        cl = ROOT / "code_law"
        if cl.exists():
            shutil.copytree(cl, Path(tmp) / "code_law")
        state = run_review(tmp, 0, "main", "head", [fname], dry_run=True)
    return "POSITIVE" if {v.status.value for v in state.vulnerabilities} & TP_STATUSES else "NEGATIVE"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lang", default="python")
    parser.add_argument("--max", type=int, default=200)
    args = parser.parse_args()

    db_path = os.environ.get("CVEFIXES_DB", str(ROOT / "benchmarks" / "CVEfixes" / "CVEfixes.db"))
    if not Path(db_path).exists():
        print(f"CVEfixes DB not found at {db_path}. Set CVEFIXES_DB env var.")
        return

    ext = LANG_EXT.get(args.lang.lower(), ".py")
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    # CVEfixes schema: file_change table has code_before, code_after, programming_language
    cur.execute(
        "SELECT code_before, code_after FROM file_change "
        "WHERE lower(programming_language)=? AND code_before IS NOT NULL "
        "AND code_after IS NOT NULL LIMIT ?",
        (args.lang.lower(), args.max),
    )
    rows = cur.fetchall()
    con.close()

    tp = fp = tn = fn = 0
    start = time.time()
    for i, (before, after) in enumerate(rows):
        _reset_neo4j()
        r = run_on_code(before, f"cvefixes_{i}{ext}")
        if r == "POSITIVE": tp += 1
        else: fn += 1
        print(f"[{'TP' if r=='POSITIVE' else 'FN'}] before row {i}")

        _reset_neo4j()
        r = run_on_code(after, f"cvefixes_{i}_fixed{ext}")
        if r == "NEGATIVE": tn += 1
        else: fp += 1
        print(f"[{'TN' if r=='NEGATIVE' else 'FP'}] after row {i}")

    elapsed = time.time() - start
    p_ = tp/(tp+fp) if tp+fp else 0
    r_ = tp/(tp+fn) if tp+fn else 0
    f1 = 2*p_*r_/(p_+r_) if p_+r_ else 0
    res = {"dataset":"CVEfixes","lang":args.lang,"date":datetime.utcnow().isoformat(),
           "n_rows":len(rows),"tp":tp,"fp":fp,"tn":tn,"fn":fn,
           "precision":round(p_,3),"recall":round(r_,3),"f1":round(f1,3),
           "fpr":round(fp/(fp+tn) if fp+tn else 0,3),"elapsed_s":round(elapsed,1)}
    print(json.dumps(res, indent=2))
    out = RESULTS_DIR / f"cvefixes_{args.lang}_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"
    out.write_text(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
