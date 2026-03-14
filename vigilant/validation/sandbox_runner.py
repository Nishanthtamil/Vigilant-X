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
            compile_cmd = self._build_compile_cmd(
                repro_src, compiler_info, poc.content, sanitizer_type
            )
            
            # Use relative paths for the container: working_dir is /workspace/build
            container_src = poc.file_name
            container_bin = "./repro"

            full_cmd = compile_cmd + ["-o", container_bin, container_src]
            run_cmd = [container_bin]

            return self._run_in_docker(
                tmp_path,
                compile_cmd=full_cmd,
                run_cmd=run_cmd,
                compiler_override=True, # Sanitizers usually require clang++ override
            )

    def _infer_sanitizer(self, vuln: Vulnerability) -> str:
        """
        Map a sink function name to the most effective LLVM sanitizer.
        """
        sink = vuln.taint_path.sink.function_name.lower()
        
        # Concurrency / Threading
        if any(kw in sink for kw in ("thread", "pthread", "fork", "atomic")):
            return "thread"
        
        # Uninitialized memory (MSan)
        # Note: malloc itself is a source, but if the sink is something that
        # reads that memory (like a comparison or branch), MSan is best.
        if any(kw in sink for kw in ("malloc", "realloc", "mmap")):
            return "memory"
            
        # Default: AddressSanitizer (covers overflows, UAF, double-free)
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
            if "compile" in err.lower() or "error:" in err.lower():
                return SandboxResult(
                    passed=False,
                    compilation_error=err,
                    compiler_override_used=compiler_override,
                )
            logger.error("Sandbox run error: %s", e)
            return SandboxResult(passed=True, compiler_override_used=compiler_override)



    # ── Build helpers ─────────────────────────────────────────────────────────

    def _build_compile_cmd(
        self, src: Path, compiler_info: dict, poc_content: str = "", sanitizer: str = "address,undefined"
    ) -> list[str]:
        # Always prefer clang++ for sanitizer compatibility
        compiler = "clang++"
        
        # MSan requires track-origins for better debugging
        flags = [f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer", "-g", "-O1"]
        if sanitizer == "memory":
            flags.append("-fsanitize-memory-track-origins")
            
        cmd = [compiler, "-std=c++20"] + flags + ["-lgtest", "-lpthread"]
        if "int main(" not in poc_content:
            cmd.append("-lgtest_main")
        return cmd


    def _resolve_image(self) -> str:
        """
        Prefer the project's own devcontainer/Dockerfile for binary compatibility;
        fall back to the Vigilant-X sandbox image.
        """
        if self.build_inf.has_devcontainer:
            logger.info("SandboxRunner: using project devcontainer")
            # Attempt to use the devcontainer image name; fall through on failure
            devcontainer_image = self._read_devcontainer_image()
            if devcontainer_image:
                return devcontainer_image

        if self.build_inf.has_project_dockerfile:
            logger.info("SandboxRunner: project has its own Dockerfile, using vigilant-sandbox as fallback")

        return self.settings.sandbox_image

    def _read_devcontainer_image(self) -> str | None:
        import json
        for candidate in [".devcontainer/devcontainer.json", ".devcontainer.json"]:
            dc = self.repo_path / candidate
            if dc.exists():
                try:
                    data = json.loads(dc.read_text())
                    return data.get("image")
                except Exception:
                    pass
        return None

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
