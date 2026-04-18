"""
vigilant/validation/sandbox_runner.py
───────────────────────────────────────
Runs a generated repro.cpp inside a Docker sandbox compiled with LLVM Sanitizers.

Key features:
- Build-system-aware: reuses project devcontainer / Dockerfile if present;
  otherwise builds from the vigilant-x-sandbox image.
- Clang-Override: always compiles with clang++ for ASan/LibFuzzer compatibility,
  even if the target project uses GCC.
- Read-only repo mount: /repo is mounted ro; only /workspace/build is writable.
- Z3 memory limit: host-side enforced; sandbox itself runs with a Docker memory cap.
"""

from __future__ import annotations

import logging
import re
import tempfile
import uuid
from pathlib import Path

import docker  # type: ignore[import]
from docker.errors import ContainerError, ImageNotFound

from vigilant.config import BuildInference, get_settings
from vigilant.models import PoCFile, SandboxResult, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# ASan / TSan / MSan / UBSan output patterns
# ─────────────────────────────────────────────────────────────────────────────

CRASH_PATTERNS = [
    (re.compile(r"heap-buffer-overflow", re.I), "heap-buffer-overflow", "ASan"),
    (re.compile(r"stack-buffer-overflow", re.I), "stack-buffer-overflow", "ASan"),
    (re.compile(r"use-after-free", re.I), "use-after-free", "ASan"),
    (re.compile(r"double-free", re.I), "double-free", "ASan"),
    (re.compile(r"heap-use-after-free", re.I), "heap-use-after-free", "ASan"),
    (re.compile(r"data race", re.I), "data-race", "TSan"),
    (re.compile(r"use of uninitialized value", re.I), "uninit-value", "MSan"),
    (re.compile(r"SUMMARY: UndefinedBehaviorSanitizer", re.I), "undefined-behavior", "UBSan"),
    (re.compile(r"SUMMARY: MemorySanitizer", re.I), "msan-crash", "MSan"),
    (re.compile(r"SUMMARY: AddressSanitizer", re.I), "asan-crash", "ASan"),
]

STACK_TRACE_RE = re.compile(
    r"(#\d+\s+0x[0-9a-f]+ in .+?)(?=\n#|\Z)", re.MULTILINE | re.DOTALL
)


class SandboxRunner:
    """
    Compiles and executes a PoC inside a Docker container, then parses sanitizer output.
    """

    def __init__(self, repo_path: Path) -> None:
        self.settings = get_settings()
        self.repo_path = repo_path
        self.build_inf = BuildInference(repo_path)
        self.docker_client = docker.from_env()

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, vuln: Vulnerability, poc: PoCFile) -> SandboxResult:
        """
        Execute the PoC in the sandbox and return a SandboxResult.
        """
        if vuln.status == VulnerabilityStatus.ADVISORY:
            return SandboxResult(passed=True)

        with tempfile.TemporaryDirectory(prefix="vigilant_sandbox_") as tmp:
            tmp_path = Path(tmp)
            repro_src = tmp_path / poc.file_name
            repro_src.write_text(poc.content)

            # Determine best sanitizer for this vulnerability type
            sanitizer_type = self._infer_sanitizer(vuln)
            
            compiler_info = self.build_inf.sandbox_compiler_flags()
            
            # --- Verification Matrix ---
            file_meta = {"opt_level": "-O1", "flags": []}
            if vuln.taint_path and vuln.taint_path.sink and vuln.taint_path.sink.file_path:
                file_meta = self.build_inf.get_file_metadata(vuln.taint_path.sink.file_path)

            # Matrix: [ (OptLevel, Compiler) ]
            # We always run the project's own level first, then fall back to high optimization 
            # to detect optimization-induced UB.
            matrix = [
                ("-O0", "clang++"),  # Baseline: no optimizations, best for ASan
                (file_meta.get("opt_level", "-O1"), "clang++"),
                ("-O3", "clang++"),  # Catch UB optimized away or introduced at O3
                ("-O2", "clang++")   # O2 sweep to catch UB that O3 optimises away
            ]

            final_result = SandboxResult(passed=True)
            for opt_level, compiler_override in matrix:
                logger.info("SandboxRunner: running matrix entry (%s, %s)", opt_level, compiler_override)
                compile_cmd = self._build_compile_cmd(
                    repro_src, compiler_info, poc.content, sanitizer_type, 
                    file_meta.get("flags", []), opt_level, compiler_override
                )
                
                # Determine if this is an override compared to project defaults
                project_compiler = compiler_info.get("compiler", "g++")
                is_override = (compiler_override != project_compiler)

                run_cmd = ["./repro"]

                current_result = self._run_in_docker(
                    tmp_path,
                    compile_cmd=compile_cmd,
                    run_cmd=run_cmd,
                    compiler_override=is_override, 
                )
                
                if not current_result.passed:
                    # Found a crash! Return this result as it's the most critical
                    logger.info("SandboxRunner: vulnerability verified in matrix entry (%s, %s)", opt_level, compiler_override)
                    return current_result
                
                final_result = current_result # Keep the last clean result if none fail

            return final_result

    def _infer_sanitizer(self, vuln: Vulnerability) -> str:
        """
        Map a vulnerability to the most effective LLVM sanitizer.
        requires_msan=True means the Z3 proof involved uninitialized memory —
        ASan will not catch this class of bug.
        """
        # Explicit MSan requirement from Z3 proof (uninit-read/CWE457 pattern)
        if getattr(vuln, "requires_msan", False):
            return "memory"

        summary = vuln.summary.lower()
        if "cwe-457" in summary or "uninitialized" in summary:
            return "memory"

        sink = vuln.taint_path.sink.function_name.lower()

        # Concurrency / threading — TSan is the correct tool
        if any(kw in sink for kw in ("thread", "pthread", "fork", "atomic")):
            return "thread"

        # malloc/realloc/mmap as sinks often indicate uninit-read
        if any(kw in sink for kw in ("malloc", "realloc", "mmap")):
            return "memory"

        # Default: AddressSanitizer covers overflows, UAF, double-free
        return "address,undefined"

    # ── Docker execution ──────────────────────────────────────────────────────

    def _run_in_docker(
        self,
        tmp_path: Path,
        compile_cmd: list[str],
        run_cmd: list[str],
        compiler_override: bool,
    ) -> SandboxResult:
        image = self._resolve_image()
        container_id = f"vigilant-sandbox-{uuid.uuid4().hex[:8]}"

        # Volume mounts:
        #   /repo  → repo source tree (read-only)
        #   /workspace/build → writable build output
        volumes = {
            str(self.repo_path): {"bind": "/repo", "mode": "ro"},
            str(tmp_path): {"bind": "/workspace/build", "mode": "rw"},
        }

        script = " && ".join([
            " ".join(compile_cmd),
            " ".join(run_cmd),
        ])

        logger.info("SandboxRunner: launching container '%s' with script: %s", container_id, script)
        container = None
        try:
            container = self.docker_client.containers.run(
                image=image,
                command=["/bin/bash", "-c", script],
                name=container_id,
                volumes=volumes,
                working_dir="/workspace/build",
                mem_limit="1g",
                memswap_limit="1g",
                network_disabled=True,
                detach=True,
            )
            # Enforce timeout host-side
            try:
                result = container.wait(timeout=self.settings.sandbox_timeout_seconds)
                exit_code = result.get("StatusCode", 0)
                logger.info("SandboxRunner: container finished with exit_code=%d", exit_code)
            except Exception:
                logger.warning("Sandbox run timed out after %d seconds", self.settings.sandbox_timeout_seconds)
                try:
                    container.kill()
                except Exception:
                    pass
                exit_code = 124 # Timeout exit code

            output = container.logs(stdout=True, stderr=True)
            container.remove()

            raw_output = output.decode("utf-8", errors="replace") if output else ""
            if not raw_output and exit_code != 0:
                raw_output = f"Container failed with exit code {exit_code} but produced no output."
            
            return self._parse_output(raw_output, compiler_override)


        except Exception as e:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

            err = str(e)
            logger.error("Sandbox infrastructure error: %s", e)
            return SandboxResult(
                passed=False, 
                compilation_error=f"Sandbox infrastructure error: {err}",
                compiler_override_used=compiler_override
            )



    # ── Build helpers ─────────────────────────────────────────────────────────

    def _build_compile_cmd(
        self, src: Path, compiler_info: dict, poc_content: str = "", sanitizer: str = "address,undefined",
        extra_flags: list[str] | None = None, opt_level: str = "-O1", compiler_override: str = "clang++"
    ) -> list[str]:
        compiler = compiler_override
        flags = [f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer", "-g", opt_level]
        libs = ["-lpthread"]

        if sanitizer == "memory":
            flags.extend([
                "-fsanitize-memory-track-origins",
                "-stdlib=libc++",
                "-I/msan-libs/include/c++/v1",
                "-L/msan-libs/lib",
            ])
            libs.extend(["-lgtest", "-lc++", "-lc++abi", "-Wl,-rpath,/msan-libs/lib"])
        else:
            libs.append("-lgtest")

        cmd = [compiler, "-std=c++20", src.name] + flags + (extra_flags or []) + libs + ["-o", "repro"]
        if "int main(" not in poc_content:
            cmd.append("-lgtest_main")
        return cmd
    def _resolve_image(self) -> str:
        """
        Always use the trusted Vigilant-X sandbox image.
        Project-specific Dockerfiles are ignored for security reasons (sandbox escape prevention).
        """
        if self.build_inf.has_project_dockerfile or self.build_inf.has_devcontainer:
            logger.warning("SandboxRunner: Project has a Dockerfile/devcontainer, but it is ignored for security. Using trusted base image.")
            
        return self.settings.sandbox_image

    # ── Output parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_output(raw_output: str, compiler_override: bool) -> SandboxResult:
        # Compilation error check
        if re.search(r"\berror:\s", raw_output) and "AddressSanitizer" not in raw_output:
            return SandboxResult(
                passed=False,
                compilation_error=raw_output[:2000],
                raw_output=raw_output,
                compiler_override_used=compiler_override,
            )

        # Check for sanitizer crashes
        for pattern, crash_type, sanitizer in CRASH_PATTERNS:
            if pattern.search(raw_output):
                stack_match = STACK_TRACE_RE.search(raw_output)
                stack_trace = stack_match.group(0)[:3000] if stack_match else raw_output[:1000]
                return SandboxResult(
                    passed=False,
                    crash_type=crash_type,
                    sanitizer=sanitizer,
                    stack_trace=stack_trace,
                    raw_output=raw_output[:4000],
                    compiler_override_used=compiler_override,
                )

        return SandboxResult(
            passed=True,
            raw_output=raw_output[:2000],
            compiler_override_used=compiler_override,
        )
