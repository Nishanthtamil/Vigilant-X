# Vigilant-X Benchmark Results

## Methodology
- **BigVul-C**: 2,000 pairs from MSR 2020 dataset (1,000 before/after CVE commits, C language)
- **Juliet**: Full NIST Juliet Test Suite, CWE121/CWE416/CWE415/CWE457, 200 bad + 200 good per CWE
- **CVEfixes-Python**: 500 pairs from CVEfixes dataset, Python files
- **CVEfixes-JS**: 300 pairs from CVEfixes dataset, JavaScript files
- TP criterion: `SANDBOX_VERIFIED | PROVEN | FUZZ_VERIFIED | LIKELY` with confidence ≥ 0.85
- FP criterion: any TP-status finding on a "fixed" (clean) file

## Results

| Dataset         | Precision | Recall | F1    | FPR   | N pairs | Date       |
|-----------------|-----------|--------|-------|-------|---------|------------|
| BigVul-C        | —         | —      | —     | —     | 2000    | run pending|
| Juliet CWE121   | —         | —      | —     | —     | 400     | run pending|
| Juliet CWE416   | —         | —      | —     | —     | 400     | run pending|
| Juliet CWE415   | —         | —      | —     | —     | 400     | run pending|
| Juliet CWE457   | —         | —      | —     | —     | 400     | run pending|
| CVEfixes-Python | —         | —      | —     | —     | 500     | run pending|
| CVEfixes-JS     | —         | —      | —     | —     | 300     | run pending|

## Target

| Metric    | Target  | Rationale                                      |
|-----------|---------|------------------------------------------------|
| Precision | ≥ 0.95  | Zero-noise: every finding must be real         |
| Recall    | ≥ 0.85  | Must catch 85%+ of real CVEs in the corpus     |
| FPR       | ≤ 0.05  | Max 5% false alarm rate on clean code          |
| P50 latency | ≤ 90s | Must be faster than CI timeout on typical PRs  |

_Results auto-updated by CI job `bench` in `.github/workflows/vigilant_x.yml`._
