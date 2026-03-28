"""
tests/test_sandbox_runner.py
─────────────────────────────
Integration tests for SandboxRunner.
Requires Docker to be running on the host.
Mark: pytest -m integration
"""

import pytest
from pathlib import Path
from vigilant.models import PoCFile, Vulnerability, VulnerabilityStatus
import uuid


@pytest.fixture
def minimal_vuln():
    from vigilant.models import TaintNode, TaintPath
    path = TaintPath(
        path_id=str(uuid.uuid4()),
        source=TaintNode(
            node_id=str(uuid.uuid4()),
            file_path="main.cpp", function_name="get_input",
            line_number=5, node_role="SOURCE", label="argv",
        ),
        sink=TaintNode(
            node_id=str(uuid.uuid4()),
            file_path="utils.cpp", function_name="memcpy",
            line_number=42, node_role="SINK", label="memcpy",
        ),
        crosses_files=True,
        rule_severity="CRITICAL",
    )
    return Vulnerability(
        vuln_id=str(uuid.uuid4()),
        taint_path=path,
        status=VulnerabilityStatus.PROVEN,
        z3_formula="input_length > buffer_size",
        confidence=0.95,
        summary="Heap buffer overflow via memcpy",
    )


@pytest.fixture
def crashing_poc():
    """A PoC that intentionally triggers a heap-buffer-overflow via ASan."""
    return PoCFile(
        file_name="repro.cpp",
        content="""
#include <cstring>
#include <cstdlib>

// Vigilant-X test: intentional heap-buffer-overflow for sandbox validation
int main() {
    char* buf = (char*)malloc(64);
    // Explicit heap buffer overflow
    buf[128] = 'A';
    free(buf);
    return 0;
}
""",
        mocking_framework="none",
        build_flags="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1",
    )


@pytest.mark.integration
def test_sandbox_detects_heap_overflow(crashing_poc, minimal_vuln, tmp_path):
    """Sandbox should detect heap-buffer-overflow and return passed=False."""
    from vigilant.validation.sandbox_runner import SandboxRunner

    # Use tmp_path as a fake repo root (no DevContainer/Dockerfile there)
    runner = SandboxRunner(repo_path=tmp_path)

    result = runner.run(minimal_vuln, crashing_poc)

    assert not result.passed, "Expected sandbox to detect a crash"
    assert result.crash_type != "", f"Expected crash type, got empty string. Raw: {result.raw_output[:200]}"
    assert "ASan" in result.sanitizer or "address" in result.crash_type.lower(), (
        f"Expected ASan sanitizer, got: {result.sanitizer}"
    )


@pytest.mark.integration
def test_sandbox_passes_clean_code(minimal_vuln, tmp_path):
    """Clean code should pass the sandbox without a crash."""
    from vigilant.validation.sandbox_runner import SandboxRunner

    clean_poc = PoCFile(
        file_name="repro.cpp",
        content="""
#include <cstring>
#include <vector>
int main() {
    // C++20 safe: vector manages bounds automatically
    std::vector<char> buf(64);
    const char input[] = "hello";
    memcpy(buf.data(), input, sizeof(input));  // sizeof(input)=6, buf=64 — safe
    return 0;
}
""",
        mocking_framework="none",
    )

    runner = SandboxRunner(repo_path=tmp_path)
    result = runner.run(minimal_vuln, clean_poc)

    assert result.passed, f"Expected clean code to pass. Crash: {result.crash_type}. Output: {result.raw_output[:300]}"


@pytest.mark.integration
def test_sandbox_advisory_skips(minimal_vuln, tmp_path):
    """ADVISORY vulnerabilities should not invoke the sandbox."""
    from vigilant.validation.sandbox_runner import SandboxRunner

    minimal_vuln.status = VulnerabilityStatus.ADVISORY
    runner = SandboxRunner(repo_path=tmp_path)
    poc = PoCFile(content="// advisory", mocking_framework="none")

    result = runner.run(minimal_vuln, poc)
    assert result.passed  # nothing ran
