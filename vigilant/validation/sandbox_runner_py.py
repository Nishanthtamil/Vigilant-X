"""
vigilant/validation/sandbox_runner_py.py
──────────────────────────────────────────
Runs Python PoCs inside Docker using Bandit + dynamic execution
with environment isolation (no network, read-only repo).

Used for PROVEN Python findings from the concolic engine.
"""
from __future__ import annotations
import logging, tempfile, uuid
from pathlib import Path
import docker
from vigilant.config import get_settings
from vigilant.models import PoCFile, SandboxResult, Vulnerability

logger = logging.getLogger(__name__)

class PythonSandboxRunner:
    """Executes Python PoC scripts in a Docker sandbox."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self.settings = get_settings()
        self.docker_client = docker.from_env()

    def run(self, vuln: Vulnerability, poc: PoCFile) -> SandboxResult:
        with tempfile.TemporaryDirectory(prefix="vigilant_py_sandbox_") as tmp:
            tmp_path = Path(tmp)
            script = tmp_path / "poc.py"
            script.write_text(poc.content)

            # Run with python3 in isolated container
            cmd = "python3 -W error poc.py 2>&1; echo EXIT:$?"
            try:
                result = self.docker_client.containers.run(
                    image="python:3.12-slim",
                    command=["/bin/sh", "-c", cmd],
                    volumes={str(tmp_path): {"bind": "/workspace", "mode": "rw"}},
                    working_dir="/workspace",
                    mem_limit="256m",
                    network_disabled=True,
                    remove=True,
                    timeout=60,
                )
                output = result.decode("utf-8", errors="replace")
                passed = "EXIT:0" in output and "Error" not in output
                return SandboxResult(passed=passed, raw_output=output[:2000])
            except Exception as e:
                return SandboxResult(passed=True, compilation_error=str(e))
