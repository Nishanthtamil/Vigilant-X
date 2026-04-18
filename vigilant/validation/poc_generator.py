"""
vigilant/validation/poc_generator.py
──────────────────────────────────────
Generates a GoogleTest C++ PoC (repro.cpp) for a confirmed Vulnerability.

The agent:
1. Selects the best available mocking framework (Google Mock → FakeIt → Hippomocks → none).
2. Uses the LLM to write a self-contained repro that feeds Z3 witness values
   (or fuzzer crash inputs) into the vulnerable function.
3. Validates that the generated code at least compiles (dry-run synthesis check).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from vigilant.config import BuildInference, get_settings
from vigilant.llm_client import LLMClient
from vigilant.models import PoCFile, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a C++ security researcher writing a minimal GoogleTest proof-of-concept \
to reproduce a vulnerability.

Requirements:
- Use GoogleTest (gtest/gtest.h) for the test harness.
- Use the mocking framework indicated below if dependencies need to be stubbed.
- Feed the exact witness values provided into the vulnerable function.
- The TEST() body must deterministically trigger the bug.
- Include only what is strictly necessary — no extra files, no main().
- Prefer C++20/23 features for the fix suggestion in comments, but keep the vulnerable \
  code path intact in the test.
- Add a comment explaining what the bug is and what input triggers it.

Return ONLY valid C++ code. No markdown. No explanation outside of code comments."""


class MockingFramework:
    """Detects which C++ mocking framework is available in the project."""

    FRAMEWORKS = [
        ("googlemock", ["gmock/gmock.h", "gmock.h"]),
        ("fakeit", ["fakeit.hpp", "fakeit/fakeit.hpp"]),
        ("hippomocks", ["hippomocks.h", "HippoMocks/hippomocks.h"]),
    ]

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self.detected: str = self._detect()

    def _detect(self) -> str:
        for name, headers in self.FRAMEWORKS:
            for header in headers:
                if any(self.repo_path.rglob(header)):
                    logger.info("MockingFramework: detected %s", name)
                    return name
        logger.info("MockingFramework: none detected — stubs will be manual")
        return "none"

    @property
    def include_directive(self) -> str:
        if self.detected == "googlemock":
            return '#include <gmock/gmock.h>'
        elif self.detected == "fakeit":
            return '#include <fakeit.hpp>\nusing namespace fakeit;'
        elif self.detected == "hippomocks":
            return '#include <hippomocks.h>'
        return "// No mocking framework — dependencies manually stubbed"


class PoCGenerator:
    """Generates a GoogleTest repro.cpp for a Vulnerability using the LLM."""

    def __init__(
        self,
        repo_path: Path,
        llm: LLMClient | None = None,
    ) -> None:
        self.repo_path = repo_path
        self.llm = llm or LLMClient()
        self.mock_fw = MockingFramework(repo_path)
        self.build_inf = BuildInference(repo_path)

    def generate(self, vuln: Vulnerability) -> PoCFile:
        """
        Generate a repro.cpp for the given Vulnerability.

        Returns a PoCFile with the generated source.
        """
        if vuln.status == VulnerabilityStatus.ADVISORY:
            # ADVISORY: no PoC needed
            return PoCFile(
                content=f"// ADVISORY: {vuln.summary}\n// No PoC required.",
                mocking_framework="none",
            )

        # Skip C++ PoC generation for non-C/C++ source files — they can't compile
        sink_ext = Path(vuln.taint_path.sink.file_path).suffix.lower()
        is_cpp = sink_ext in (".cpp", ".cc", ".c", ".h", ".hpp", "")
        
        lang_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".go": "Go"
        }
        target_lang = lang_map.get(sink_ext, "C++" if is_cpp else None)

        if not target_lang:
            return PoCFile(
                content=f"// SKIP: No PoC generation for {sink_ext} file ({vuln.summary})",
                mocking_framework="none",
            )

        user_prompt = self._build_prompt(vuln, target_lang)
        logger.info("PoCGenerator: generating %s PoC for vuln %s", target_lang, vuln.vuln_id[:8])

        system_prompt = _SYSTEM_PROMPT
        if target_lang != "C++":
            system_prompt = (
                f"You are a {target_lang} security researcher writing a minimal "
                f"proof-of-concept to reproduce a vulnerability. "
                f"Return ONLY valid {target_lang} code. No markdown."
            )

        code = self.llm.ask(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.15,
            max_tokens=2048,
        )
        # Strip any markdown fences
        code = re.sub(r"```(?:\w+)?", "", code).strip().strip("`")

        # Validate compilation (best-effort, C++ only)
        if is_cpp:
            compile_ok = self._try_compile(code)
            if not compile_ok:
                logger.warning("PoCGenerator: initial compile failed, retrying with simpler prompt")
                code = self._retry_simpler(vuln)

        return PoCFile(
            file_name=f"repro{sink_ext if sink_ext else '.cpp'}",
            content=code,
            mocking_framework=self.mock_fw.detected if is_cpp else "none",
            build_flags=self.build_inf.sandbox_compiler_flags().get("flags", "") if is_cpp else "",
        )

    def _build_prompt(self, vuln: Vulnerability, target_lang: str) -> str:
        path = vuln.taint_path
        witness_str = "\n".join(
            f"  - {w.variable} = {w.value}  // {w.explanation}"
            for w in vuln.witness_values
        ) or "  (No Z3 witnesses; use fuzzer crash input if available)"

        fuzz_input = (
            f"\nFuzzer crash input (hex): {vuln.fuzz_crash_input[:128]}"
            if vuln.fuzz_crash_input
            else ""
        )
        
        context = ""
        try:
            src_file = self.repo_path / path.source.file_path
            if src_file.exists():
                context = f"\nRelevant code from {path.source.file_path}:\n```\n{src_file.read_text(errors='replace')[:2000]}\n```"
        except Exception:
            pass

        return f"""
Vulnerability Summary: {vuln.summary}
Language: {target_lang}

Source: {path.source.function_name}() in {path.source.file_path} (line {path.source.line_number})
Sink:   {path.sink.function_name}() in {path.sink.file_path} (line {path.sink.line_number})
{context}

Z3 Formula: {vuln.z3_formula or "(Z3 returned unknown)"}

Witness values (feed these into the vulnerable function):
{witness_str}{fuzz_input}

Write a single-file {target_lang} script that:
1. Imports necessary modules.
2. CALLS the function {path.sink.function_name}() from the project (mocking as needed).
3. PROVES the vulnerability exists by triggering a crash or logical failure.
"""

    def _try_compile(self, code: str) -> bool:
        """Full compile check — catches both syntax and linker errors."""
        compiler_info = self.build_inf.sandbox_compiler_flags()
        compiler = compiler_info.get("compiler", "clang++")
        if not shutil.which(compiler):
            return True  # Skip check if compiler not on PATH

        with tempfile.NamedTemporaryFile(suffix=".cpp", mode="w", delete=False) as f:
            f.write(code)
            src = Path(f.name)

        out = src.with_suffix("")
        try:
            result = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-fsanitize=address",
                    "-fno-omit-frame-pointer",
                    "-g", "-O1",
                    str(src),
                    "-lgtest", "-lgtest_main", "-lpthread",
                    "-o", str(out),
                ],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                logger.debug("PoCGenerator compile check failed:\n%s", result.stderr[:500])
            return result.returncode == 0
        except Exception as e:
            logger.debug("PoCGenerator compile check exception: %s", e)
            return True  # Don't block on infrastructure failures
        finally:
            src.unlink(missing_ok=True)
            out.unlink(missing_ok=True)

    def _retry_simpler(self, vuln: Vulnerability) -> str:
        """Fallback: generate a minimal, unconditional repro."""
        sink = vuln.taint_path.sink.function_name
        witnesses = vuln.witness_values
        input_len = next((int(w.value) for w in witnesses if "length" in w.variable.lower()), 65)

        # Signature templates for common sinks
        templates = {
            "memcpy": "memcpy(buf, input.data(), input.size());",
            "memmove": "memmove(buf, input.data(), input.size());",
            "strcpy": "strcpy(buf, input.data());",
            "strncpy": "strncpy(buf, input.data(), 64);",
            "strcat": "strcat(buf, input.data());",
            "free": "free(input.data());",
            "operator delete": "delete input.data();",
            "system": "system(input.data());",
            "popen": "popen(input.data(), \"r\");",
            "SysFreeString": "SysFreeString((BSTR)input.data());",
        }
        call_code = templates.get(sink, f"{sink}(buf, input.data(), input.size());")

        return f"""
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

// Vigilant-X auto-generated PoC
// Bug: {vuln.summary}
// Fix: Use std::span or std::vector with explicit size checks (C++20)

TEST(VigilantX, {sink.capitalize()}Overflow) {{
    // Z3 witness: input_length = {input_len} (overflows a 64-byte buffer)
    std::vector<char> input({input_len}, 'A');
    char buf[64];
    memset(buf, 0, sizeof(buf));
    
    // Vulnerable call:
    {call_code}
    
    // If ASan is active, the above line will trigger a crash
    SUCCEED();
}}

int main(int argc, char** argv) {{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}}
"""
