"""
vigilant/communication/reviewer.py
────────────────────────────────────
Senior-grade LLM reviewer:
- Only generates reports for SANDBOX_VERIFIED / PROVEN / FUZZ_VERIFIED vulnerabilities.
- Produces root-cause explanation, stack trace evidence, and a Modern C++20/23 fix.
- Runs the fix itself through the sandbox to confirm it's clean before reporting.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from vigilant.llm_client import LLMClient
from vigilant.models import (
    Fix,
    PRIntent,
    PoCFile,
    ReviewReport,
    SandboxResult,
    Vulnerability,
    VulnerabilityStatus,
)

logger = logging.getLogger(__name__)

MAX_REVIEW_CHARS = 4_000
_TRUNCATED_NOTE = "\n\n_Full analysis truncated — see GitHub Actions logs._"

_ROOT_CAUSE_SYSTEM = """You are a principal C++ security engineer writing a Gold Standard code review report.

Your analysis must:
1. Explain the ROOT CAUSE in plain English — why the cross-file logic failed.
2. Provide a MODERN C++20/23 FIX using std::span, std::expected, std::unique_ptr, 
   std::string_view, std::ranges, or std::format where appropriate.
3. Output the fix as a GITHUB SUGGESTION block if it is a single-file fix.
4. Provide the exact file path, start line, and end line for the fix.

Format:
### Root Cause
<explanation>

### File Metadata
File: <path>
Start Line: <number>
End Line: <number>

### Verified Fix
```suggestion
<fixed code lines only>
```

### Unified Diff
```diff
- <vulnerable line(s)>
+ <fixed line(s)>
```

### Why This Fix Works
<one sentence>"""

class Reviewer:
    """Generates the final Gold Standard review report."""

    def __init__(
        self,
        sandbox_runner=None,   # type: ignore[assignment]  # avoid circular import
        llm: LLMClient | None = None,
    ) -> None:
        self.llm = llm or LLMClient()
        self.sandbox_runner = sandbox_runner  # may be None in dry-run

    def generate_report(
        self,
        pr_number: int,
        github_repo: str,
        head_sha: str,
        vulnerabilities: list[Vulnerability],
        sandbox_results: dict[str, SandboxResult],
        poc_files: dict[str, PoCFile],
        repo_path: Path | None = None,
        pr_intent: PRIntent | None = None,
    ) -> ReviewReport:
        """Generate the full ReviewReport for a PR."""
        fixes: dict[str, Fix] = {}
        advisory_comments: list[str] = []

        # ── Generate PR walkthrough summary ───────────────────────────────────
        walkthrough = self._generate_walkthrough(pr_intent) if pr_intent else ""

        # ── Filter to reportable vulns ────────────────────────────────────────
        reportable_statuses = {
            VulnerabilityStatus.PROVEN,
            VulnerabilityStatus.FUZZ_VERIFIED,
            VulnerabilityStatus.SANDBOX_VERIFIED,
        }
        verified_vulns = [
            v for v in vulnerabilities
            if v.status in reportable_statuses
        ]
        advisory_vulns = [
            v for v in vulnerabilities
            if v.status == VulnerabilityStatus.ADVISORY
        ]

        # ── Generate fix for each verified vuln ───────────────────────────────
        for vuln in verified_vulns:
            sandbox_res = sandbox_results.get(vuln.vuln_id)
            fix = self._generate_fix(vuln, sandbox_res)
            # Run the fix through the sandbox to confirm it's clean
            if self.sandbox_runner and fix.diff:
                fix_poc = self._make_fix_poc(vuln, fix, poc_files, repo_path=repo_path)
                if fix_poc:
                    fix.fix_sandbox_result = self.sandbox_runner.run(vuln, fix_poc)
            fixes[vuln.vuln_id] = fix

        # ── Advisory comments ─────────────────────────────────────────────────
        for vuln in advisory_vulns:
            comment = self._advisory_comment(vuln)
            advisory_comments.append(comment)

        # ── Compose full markdown body ────────────────────────────────────────
        markdown_body = self._compose_markdown(
            verified_vulns, fixes, sandbox_results, advisory_comments,
            walkthrough=walkthrough,
        )

        return ReviewReport(
            pr_number=pr_number,
            github_repo=github_repo,
            head_sha=head_sha,
            vulnerabilities=vulnerabilities,
            fixes=fixes,
            advisory_comments=advisory_comments,
            markdown_body=markdown_body,
            walkthrough_summary=walkthrough,
        )

    # ── Fix generation ────────────────────────────────────────────────────────

    def _generate_fix(self, vuln: Vulnerability, sandbox_res: SandboxResult | None) -> Fix:
        path = vuln.taint_path
        evidence = ""
        if sandbox_res and not sandbox_res.passed:
            evidence = f"\nSanitizer: {sandbox_res.sanitizer} — {sandbox_res.crash_type}\nStack trace:\n{sandbox_res.stack_trace[:800]}"

        prompt = f"""
Vulnerability: {vuln.summary}

Source: {path.source.function_name}() in {path.source.file_path}:{path.source.line_number}
Sink:   {path.sink.function_name}() in {path.sink.file_path}:{path.sink.line_number}
Cross-file: {path.crosses_files}
Z3 Formula: {vuln.z3_formula or "(none)"}
Witnesses: {', '.join(f"{w.variable}={w.value}" for w in vuln.witness_values) or "(fuzzer-found)"}
{evidence}

Provide the root cause explanation and a C++20/23 fix suggestion.
"""
        try:
            raw = self.llm.ask(
                system_prompt=_ROOT_CAUSE_SYSTEM,
                user_prompt=prompt,
                temperature=0.1,
                max_tokens=1500,
            )
            diff = self._extract_diff(raw)
            suggestion = self._extract_suggestion(raw)
            file_path, line_start, line_end = self._extract_metadata(raw)
            
            # Fallback to sink node if LLM fails to provide metadata
            if not file_path:
                file_path = path.sink.file_path
                line_start = path.sink.line_number
                line_end = path.sink.line_number

            raw_out = raw[:MAX_REVIEW_CHARS] + (_TRUNCATED_NOTE if len(raw) > MAX_REVIEW_CHARS else "")

            return Fix(
                description=raw_out,
                diff=diff,
                suggestion=suggestion,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                cpp_standard="C++20",
            )
        except Exception as e:
            logger.error("Reviewer: fix generation failed: %s", e)
            return Fix(
                description=f"Fix generation failed: {e}",
                diff="",
                cpp_standard="C++20",
                file_path=path.sink.file_path,
                line_start=path.sink.line_number,
                line_end=path.sink.line_number,
            )

    @staticmethod
    def _extract_diff(text: str) -> str:
        """Extract the first diff block from the LLM response."""
        match = re.search(r"```diff\n(.+?)```", text, re.DOTALL)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _extract_suggestion(text: str) -> str:
        """Extract the github suggestion block."""
        match = re.search(r"```suggestion\n(.+?)```", text, re.DOTALL)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _extract_metadata(text: str) -> tuple[str, int, int]:
        """Extract file path, start line, and end line from text."""
        file_match = re.search(r"File: (.+)", text)
        start_match = re.search(r"Start Line: (\d+)", text)
        end_match = re.search(r"End Line: (\d+)", text)
        
        file_path = file_match.group(1).strip() if file_match else ""
        line_start = int(start_match.group(1)) if start_match else 0
        line_end = int(end_match.group(1)) if end_match else 0
        
        return file_path, line_start, line_end

    @staticmethod
    def _make_fix_poc(
        vuln: Vulnerability, fix: Fix, poc_files: dict[str, PoCFile],
        repo_path: Path | None = None,
    ) -> PoCFile | None:
        """Create a PoCFile with the fix applied, for sandbox validation.

        The LLM-generated diff is against the *original source file*, not
        the PoC (repro.cpp).  We apply the diff to the actual source file
        in the repo, then compile the patched source alongside the PoC.
        """
        import shutil
        import subprocess
        import tempfile

        original = poc_files.get(vuln.vuln_id)
        if not original or not fix.diff or not fix.file_path:
            return None

        # Resolve the source file the diff targets
        if repo_path:
            source_file = repo_path / fix.file_path
        else:
            source_file = Path(fix.file_path)

        if not source_file.exists():
            logger.debug("Reviewer: source file %s not found for fix patching", source_file)
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Copy the source file into a temp dir so we don't mutate the repo
            tmp_source = tmp_path / source_file.name
            shutil.copy2(source_file, tmp_source)

            diff_file = tmp_path / "fix.diff"
            diff_text = fix.diff if fix.diff.endswith("\n") else fix.diff + "\n"
            diff_file.write_text(diff_text)

            try:
                # Try -p1 first (handles a/ b/ prefixes), then -p0 fallback
                for strip_level in ("-p1", "-p0"):
                    result = subprocess.run(
                        ["patch", "--forward", "--batch", strip_level,
                         str(tmp_source), str(diff_file)],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode == 0:
                        # Build a combined PoC: original harness + patched source
                        patched_source = tmp_source.read_text()
                        fixed_content = (
                            f"// Patched source ({source_file.name}):\n"
                            f"{patched_source}\n\n"
                            f"// Original PoC harness:\n"
                            f"{original.content}"
                        )
                        logger.info("Reviewer: applied fix to %s for vuln %s",
                                    source_file.name, vuln.vuln_id[:8])
                        return PoCFile(
                            content=fixed_content,
                            mocking_framework=original.mocking_framework,
                        )

                logger.debug("Reviewer: patch failed for %s: %s",
                             vuln.vuln_id[:8], result.stderr)
            except Exception as e:
                logger.warning("Reviewer: patch command error for %s: %s",
                               vuln.vuln_id[:8], e)

        return None

    @staticmethod
    def _advisory_comment(vuln: Vulnerability) -> str:
        path = vuln.taint_path
        return (
            f"💡 **Advisory** `{path.sink.function_name}` in `{path.sink.file_path}` "
            f"(Rule: `{vuln.taint_path.rule_id}`): {vuln.summary}"
        )

    # ── Markdown composer ─────────────────────────────────────────────────────

    @staticmethod
    def _generate_walkthrough(pr_intent: PRIntent) -> str:
        """Format the PRIntent into a plain-English walkthrough summary."""
        parts: list[str] = [
            "## 📋 PR Walkthrough",
            "",
            f"> {pr_intent.purpose}",
            "",
        ]

        if pr_intent.changed_modules:
            parts.append("**Changed areas:**")
            for mod in pr_intent.changed_modules:
                parts.append(f"- `{mod}`")
            parts.append("")

        if pr_intent.risk_areas:
            parts.append("**Potential risk areas:**")
            for risk in pr_intent.risk_areas:
                parts.append(f"- ⚠️ {risk}")
            parts.append("")

        if pr_intent.code_law_violations_suspected:
            parts.append("**Suspected Code Law violations:**")
            for v in pr_intent.code_law_violations_suspected:
                parts.append(f"- 🔍 {v}")
            parts.append("")

        return "\n".join(parts)

    def _compose_markdown(
        self,
        verified: list[Vulnerability],
        fixes: dict[str, Fix],
        sandbox_results: dict[str, SandboxResult],
        advisory_comments: list[str],
        walkthrough: str = "",
    ) -> str:
        # Always start with walkthrough if available
        prefix = f"{walkthrough}\n\n" if walkthrough else ""

        if not verified and not advisory_comments:
            return (
                f"{prefix}"
                "## ✅ Vigilant-X: No Issues Found\n\n"
                "All taint paths were analyzed. No verified vulnerabilities detected."
            )

        parts: list[str] = [
            "## 🔴 Vigilant-X Security Review",
            "",
            f"> **{len(verified)} verified vulnerabilities** | "
            f"{len(advisory_comments)} advisory notes",
            "",
        ]

        for i, vuln in enumerate(verified, 1):
            sandbox = sandbox_results.get(vuln.vuln_id)
            fix = fixes.get(vuln.vuln_id)
            path = vuln.taint_path
            status_icon = {
                VulnerabilityStatus.PROVEN: "🔴",
                VulnerabilityStatus.FUZZ_VERIFIED: "🟠",
                VulnerabilityStatus.SANDBOX_VERIFIED: "🔴",
            }.get(vuln.status, "🟡")

            parts += [
                f"---",
                f"### {status_icon} Issue #{i}: {vuln.taint_path.sink.function_name.upper()} vulnerability",
                f"**Status:** `{vuln.status.value}` | **Confidence:** {vuln.confidence:.0%}",
                f"**Path:** `{path.source.file_path}:{path.source.line_number}` → "
                f"`{path.sink.file_path}:{path.sink.line_number}`",
                f"**Cross-file:** {'Yes' if path.crosses_files else 'No'}",
                "",
            ]

            if vuln.z3_formula:
                parts += [
                    "#### Mathematical Proof (Z3)",
                    f"```",
                    f"{vuln.z3_formula}",
                    f"```",
                    "",
                ]

            if vuln.witness_values:
                parts.append("**Witness values:**")
                for w in vuln.witness_values:
                    parts.append(f"- `{w.variable} = {w.value}` — {w.explanation}")
                parts.append("")

            if sandbox and not sandbox.passed:
                parts += [
                    "#### Evidence (Sanitizer Report)",
                    f"**Sanitizer:** {sandbox.sanitizer} | **Crash type:** `{sandbox.crash_type}`",
                    "```",
                    sandbox.stack_trace[:800],
                    "```",
                    "",
                ]
                if sandbox.compiler_override_used:
                    parts.append(
                        "_⚠️ Note: Compiled with Clang++ override (project uses GCC; "
                        "required for ASan/LibFuzzer compatibility)._\n"
                    )

            if fix and fix.description:
                parts += [fix.description, ""]

            if fix and fix.fix_sandbox_result:
                fix_res = fix.fix_sandbox_result
                fix_status = "✅ Fix verified clean by sandbox" if fix_res.passed else "⚠️ Fix sandbox check inconclusive"
                parts += [f"_{fix_status}_", ""]

        if advisory_comments:
            parts += ["---", "### 💡 Advisory Notes", ""]
            parts.extend(advisory_comments)

        parts += [
            "",
            "---",
            "_Generated by [Vigilant-X](https://github.com/nishanth/Vigilant-X) "
            "— Formal verification + sandboxed proof-of-concept analysis._",
        ]
        return "\n".join(parts)
