import os
import shutil
import time
from pathlib import Path

# Set environment variable to ensure local Neo4j is used if needed
os.environ["USE_LOCAL_NEO4J"] = "true"
os.environ["NEO4J_LOCAL_URI"] = "bolt://localhost:7688"
os.environ["NEO4J_AUTH"] = "neo4j/vigilant_local"
os.environ["SANDBOX_ALWAYS_RUN"] = "true"

from vigilant.orchestrator import run_review
from vigilant.models import VulnerabilityStatus
from vigilant.ingestion.cpg_builder import get_driver

ROOT_DIR = Path(__file__).parent.parent
BENCHMARK_REPO = ROOT_DIR / "benchmarks" / "mock_repo"
BENCHMARK_CODE_LAW = BENCHMARK_REPO / "code_law"

CASES = {
    "CWE121_Stack_Based_Buffer_Overflow": {
        "bad": """
#include <cstring>
#include <iostream>

void CWE121_bad(const char* data) {
    char dest[64];
    // BAD: data could be larger than 64 bytes
    // Trigger: data length > 64
    std::strcpy(dest, data);
    std::cout << "Data: " << dest << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc > 1) { 
        CWE121_bad(argv[1]); 
    } else {
        // Default trigger for sandbox
        char large[128];
        std::memset(large, 'A', 127);
        large[127] = '\\0';
        CWE121_bad(large);
    }
    return 0;
}
""",
        "good": """
#include <cstring>
#include <iostream>

void CWE121_good(const char* data) {
    char dest[50];
    size_t len = strlen(data);
    if (len < 50) {
        // GOOD: size checked
        std::memcpy(dest, data, len);
        dest[len] = '\\0';
        std::cout << dest << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) { CWE121_good(argv[1]); }
    return 0;
}
"""
    },
    "CWE416_Use_After_Free": {
        "bad": """
#include <cstdlib>
#include <cstring>
#include <iostream>

void CWE416_bad(const char* data) {
    char* ptr = (char*)std::malloc(100);
    std::strncpy(ptr, data, 99);
    ptr[99] = '\\0';
    std::free(ptr);
    // BAD: use after free
    std::cout << ptr[0] << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc > 1) { 
        CWE416_bad(argv[1]); 
    } else {
        CWE416_bad("test");
    }
    return 0;
}
""",
        "good": """
#include <cstdlib>
#include <cstring>
#include <iostream>

void CWE416_good(const char* data) {
    char* ptr = (char*)std::malloc(100);
    std::strncpy(ptr, data, 99);
    ptr[99] = '\\0';
    // GOOD: use before free
    std::cout << ptr[0] << std::endl;
    std::free(ptr);
}

int main(int argc, char *argv[]) {
    if (argc > 1) { 
        CWE416_good(argv[1]); 
    } else {
        CWE416_good("test");
    }
    return 0;
}
"""
    },
    "CWE415_Double_Free": {
        "bad": """
#include <cstdlib>
#include <iostream>

void CWE415_bad(bool flag) {
    char* ptr = (char*)std::malloc(100);
    if (flag) {
        std::free(ptr);
    }
    // BAD: potentially double free
    std::free(ptr);
}

int main(int argc, char *argv[]) {
    // Force the double-free path in sandbox
    CWE415_bad(true);
    return 0;
}
""",
        "good": """
#include <cstdlib>
#include <iostream>

void CWE415_good(bool flag) {
    char* ptr = (char*)std::malloc(100);
    if (flag) {
        std::free(ptr);
        ptr = nullptr;
    }
    // GOOD: safe to free nullptr
    std::free(ptr);
}

int main(int argc, char *argv[]) {
    // Test the safe path
    CWE415_good(true);
    return 0;
}
"""
    },
    "CWE457_Uninitialized_Variable": {
        "bad": """
#include <iostream>

void CWE457_bad(bool flag) {
    int val;
    if (flag) {
        val = 10;
    }
    // BAD: val might be uninitialized
    std::cout << val << std::endl;
}

int main(int argc, char *argv[]) {
    // Force the uninitialized path in sandbox
    CWE457_bad(false);
    return 0;
}
""",
        "good": """
#include <iostream>

void CWE457_good(bool flag) {
    int val = 0;
    if (flag) {
        val = 10;
    }
    // GOOD: val is initialized
    std::cout << val << std::endl;
}

int main(int argc, char *argv[]) {
    // Test the safe path
    CWE457_good(false);
    return 0;
}
"""
    }
}

def setup_benchmark_repo():
    if BENCHMARK_REPO.exists():
        shutil.rmtree(BENCHMARK_REPO)
    BENCHMARK_REPO.mkdir(parents=True)
    
    # Copy code_law so it finds the rules
    source_code_law = ROOT_DIR / "code_law"
    if source_code_law.exists():
        shutil.copytree(source_code_law, BENCHMARK_CODE_LAW)

def run_benchmarks():
    setup_benchmark_repo()
    
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    
    start_time = time.time()
    total_runs = 0
    
    for cwe, variants in CASES.items():
        for variant in ["bad", "good"]:
            file_name = f"{cwe}_{variant}.cpp"
            print(f"\\n--- Evaluating {file_name} ---")
            
            # Clear Neo4j
            try:
                driver = get_driver()
                with driver.session() as session:
                    session.run("MATCH (n) DETACH DELETE n")
            except Exception as e:
                print(f"Failed to clear Neo4j: {e}")
                
            # Write just this file to the mock repo
            for f in BENCHMARK_REPO.glob("*.cpp"):
                f.unlink()
                
            file_path = BENCHMARK_REPO / file_name
            file_path.write_text(CASES[cwe][variant])
            
            # Using dry_run=True to bypass PR posting
            try:
                state = run_review(
                    repo_path=str(BENCHMARK_REPO.absolute()),
                    pr_number=0,
                    base_sha="main",
                    head_sha="head",
                    changed_files=[file_name],
                    dry_run=True
                )
                
                # STRICT CHECK: Include SANDBOX, FUZZ, and LIKELY (Proven/DeepScan)
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
                
                if variant == "bad":
                    if has_bug:
                        print(f"[TP] correctly found bug in {file_name}")
                        tp += 1
                    else:
                        print(f"[FN] missed bug in {file_name}")
                        fn += 1
                else:
                    if has_bug:
                        print(f"[FP] incorrectly found bug in {file_name}")
                        fp += 1
                    else:
                        print(f"[TN] correctly found no bug in {file_name}")
                        tn += 1
                        
            except Exception as e:
                print(f"Error analyzing {file_name}: {e}")
                if variant == "bad":
                    fn += 1
                else:
                    fp += 1
                    
            total_runs += 1

    end_time = time.time()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_time = (end_time - start_time) / total_runs if total_runs > 0 else 0
    
    print("\\n===========================================")
    print("        VIGILANT-X BENCHMARK RESULTS       ")
    print("===========================================")
    print(f"True Positives  (TP): {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"True Negatives  (TN): {tn}")
    print(f"False Negatives (FN): {fn}")
    print("-------------------------------------------")
    print(f"Precision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    print(f"F1-Score:  {f1:.2f}")
    print(f"Avg Time per file: {avg_time:.2f} seconds")
    print("===========================================")


def run_juliet_benchmark(cwe_id: str = "CWE121", max_cases: int = 200) -> None:
    """
    Run Vigilant-X against Juliet Test Suite cases for a specific CWE.

    Download Juliet from: https://samate.nist.gov/SARD/test-suites/116
    Extract to: benchmarks/juliet/<CWE_ID>/
    Files named *_bad*.cpp should be found as vulnerable.
    Files named *_good*.cpp should be found as clean.

    Usage:
        python scripts/evaluate_benchmark.py --juliet CWE121
    """
    from pathlib import Path as _P

    juliet_path = ROOT_DIR / "benchmarks" / "juliet" / cwe_id
    if not juliet_path.exists():
        print(f"Juliet dataset for {cwe_id} not found at {juliet_path}")
        print(f"Download from https://samate.nist.gov/SARD/test-suites/116")
        print(f"and extract the {cwe_id} directory to {juliet_path}")
        return

    bad_files  = sorted(juliet_path.glob("*_bad*.cpp"))[:max_cases]
    good_files = sorted(juliet_path.glob("*_good*.cpp"))[:max_cases]
    total_files = bad_files + good_files

    if not total_files:
        print(f"No test cases found in {juliet_path}")
        return

    print(f"\nRunning Juliet {cwe_id}: {len(bad_files)} bad + {len(good_files)} good cases")

    setup_benchmark_repo()
    tp = fp = tn = fn = 0
    start_time = time.time()

    for file_path in total_files:
        is_bad = "_bad" in file_path.name
        file_name = file_path.name
        print(f"\n--- Evaluating {file_name} ---")

        # Clear Neo4j between runs
        try:
            driver = get_driver()
            with driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
        except Exception as e:
            print(f"Failed to clear Neo4j: {e}")

        for f in BENCHMARK_REPO.glob("*.cpp"):
            f.unlink()

        dest = BENCHMARK_REPO / file_name
        import shutil as _shutil
        _shutil.copy2(file_path, dest)

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
            if is_bad:
                fn += 1
            else:
                fp += 1

    elapsed = time.time() - start_time
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n{'='*50}")
    print(f"JULIET {cwe_id} BENCHMARK RESULTS")
    print(f"{'='*50}")
    print(f"True Positives  (TP): {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"True Negatives  (TN): {tn}")
    print(f"False Negatives (FN): {fn}")
    print(f"{'─'*50}")
    print(f"Precision:  {precision:.3f}")
    print(f"Recall:     {recall:.3f}")
    print(f"F1-Score:   {f1:.3f}")
    print(f"FPR:        {fpr:.3f}")
    print(f"Total time: {elapsed:.1f}s ({elapsed/len(total_files):.1f}s/file)")
    print(f"{'='*50}")


if __name__ == "__main__":
    import sys
    if "--juliet" in sys.argv:
        idx = sys.argv.index("--juliet")
        cwe = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "CWE121"
        max_n = int(sys.argv[idx + 2]) if idx + 2 < len(sys.argv) else 200
        run_juliet_benchmark(cwe, max_n)
    else:
        run_benchmarks()
