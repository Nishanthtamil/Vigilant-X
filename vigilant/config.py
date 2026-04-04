"""
vigilant/config.py
──────────────────
Settings loader (pydantic-settings), Code Law parser, and Build Inference.
"""

from __future__ import annotations

import hashlib
import os
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ─────────────────────────────────────────────────────────────────────────────
# Global settings (loaded from .env)
# ─────────────────────────────────────────────────────────────────────────────


class LLMProvider(str, Enum):
    GROQ = "groq"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM ───────────────────────────────────────────────────────────────────
    llm_provider: LLMProvider = LLMProvider.GROQ

    groq_api_key: str = ""
    groq_model: str = "meta-llama/llama-4-scout-17b-16e-instruct"

    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-5-sonnet-20241022"

    # ── Neo4j ─────────────────────────────────────────────────────────────────
    use_local_neo4j: bool = True

    neo4j_local_uri: str = "bolt://localhost:7687"
    neo4j_local_username: str = "neo4j"
    neo4j_local_password: str = "vigilant_local"

    neo4j_aura_uri: str = "neo4j+s://2a6a1b23.databases.neo4j.io"
    neo4j_aura_username: str = "neo4j"
    neo4j_aura_password: str = ""
    neo4j_aura_database: str = "neo4j"

    @property
    def neo4j_uri(self) -> str:
        return self.neo4j_local_uri if self.use_local_neo4j else self.neo4j_aura_uri

    @property
    def neo4j_username(self) -> str:
        return self.neo4j_local_username if self.use_local_neo4j else self.neo4j_aura_username

    @property
    def neo4j_password(self) -> str:
        return self.neo4j_local_password if self.use_local_neo4j else self.neo4j_aura_password

    @property
    def neo4j_database(self) -> str:
        return "neo4j" if self.use_local_neo4j else self.neo4j_aura_database

    # ── GitHub ────────────────────────────────────────────────────────────────
    github_token: str = ""
    github_webhook_secret: str = ""
    github_repo: str = ""

    # ── Sandbox ───────────────────────────────────────────────────────────────
    sandbox_always_run: bool = False
    sandbox_timeout_seconds: int = 120
    libfuzzer_timeout_seconds: int = 60
    z3_memory_limit_mb: int = 2048
    sandbox_image: str = "vigilant-x-sandbox:latest"

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = "INFO"


# Singleton
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# ─────────────────────────────────────────────────────────────────────────────
# Code Law
# ─────────────────────────────────────────────────────────────────────────────


class RuleSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # → Z3 + Sandbox path
    ADVISORY = "ADVISORY"   # → LLM-only review, no sandbox


class CodeLawRule:
    def __init__(self, data: dict[str, Any]) -> None:
        self.id: str = data["id"]
        self.severity: RuleSeverity = RuleSeverity(data["severity"])
        self.description: str = data["description"]
        self.pattern: str = data["pattern"]
        self.applies_to: list[str] = data.get("applies_to", ["**/*"])

    def is_critical(self) -> bool:
        return self.severity == RuleSeverity.CRITICAL

    def __repr__(self) -> str:
        return f"<Rule {self.id} [{self.severity}]>"


class CodeLaw:
    """Loads and provides access to Code Law rules from YAML files."""

    def __init__(self, rules_dir: Path | None = None, repo_path: Path | None = None) -> None:
        if rules_dir is None:
            rules_dir = Path(__file__).parent.parent / "code_law"
        self.rules: list[CodeLawRule] = []
        # Load default rules
        self._load(rules_dir)
        
        # Load repo-specific rules if present
        if repo_path:
            self._load_repo_rules(repo_path)

    def _load(self, rules_dir: Path) -> None:
        if not rules_dir.exists():
            return
        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            try:
                with yaml_file.open() as f:
                    data = yaml.safe_load(f)
                if data and "rules" in data:
                    for rule_data in data.get("rules", []):
                        self.rules.append(CodeLawRule(rule_data))
            except Exception as e:
                print(f"Error loading rules from {yaml_file}: {e}")

    def _load_repo_rules(self, repo_path: Path) -> None:
        """Look for .vigilant-x.yaml or vigilant-rules.yaml in the repo root."""
        for name in [".vigilant-x.yaml", "vigilant-rules.yaml", "code_law.yaml"]:
            rule_file = repo_path / name
            if rule_file.exists():
                try:
                    with rule_file.open() as f:
                        data = yaml.safe_load(f)
                    if data and "rules" in data:
                        for rule_data in data.get("rules", []):
                            self.rules.append(CodeLawRule(rule_data))
                        print(f"Loaded {len(data['rules'])} custom rules from {name}")
                except Exception as e:
                    print(f"Error loading custom rules from {rule_file}: {e}")

    @property
    def critical_rules(self) -> list[CodeLawRule]:
        return [r for r in self.rules if r.is_critical()]

    @property
    def advisory_rules(self) -> list[CodeLawRule]:
        return [r for r in self.rules if not r.is_critical()]

    def rules_for_file(self, file_path: str) -> list[CodeLawRule]:
        """Return rules whose glob patterns match the given file path."""
        matching = []
        p = Path(file_path)
        for rule in self.rules:
            for pattern in rule.applies_to:
                # Match recursive (**/) or direct (*.cpp)
                if p.match(pattern) or p.match(pattern.replace("**/", "")):
                    matching.append(rule)
                    break
        return matching


# ─────────────────────────────────────────────────────────────────────────────
# Build Inference
# ─────────────────────────────────────────────────────────────────────────────


class BuildSystem(str, Enum):
    CMAKE = "cmake"
    BAZEL = "bazel"
    MAKE = "make"
    MESON = "meson"
    UNKNOWN = "unknown"


_ALLOWED_FLAG_PREFIXES = (
    "-O", "-std=", "-I", "-D", "-W", "-f", "-m", "-g",
    "-march=", "-mtune=", "-target",
)
_BLOCKED_FLAG_PATTERNS = (
    "-fplugin", "-B", "--sysroot", "-rpath", "-Wl,",
    "-load", "-pass-plugin",
)

def _sanitize_flags(flags: list[str]) -> list[str]:
    """Filter out dangerous or irrelevant compiler flags for the sandbox."""
    safe = []
    for f in flags:
        blocked = any(f.startswith(b) for b in _BLOCKED_FLAG_PATTERNS)
        allowed = any(f.startswith(a) for a in _ALLOWED_FLAG_PREFIXES)
        if allowed and not blocked:
            safe.append(f)
    return safe


class BuildInference:
    """
    Detects the build system of a C++ repo and determines
    whether the compiler is Clang (required for LibFuzzer).
    """

    # Sentinel files for each build system
    INDICATORS: list[tuple[BuildSystem, list[str]]] = [
        (BuildSystem.CMAKE, ["CMakeLists.txt"]),
        (BuildSystem.BAZEL, ["BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel"]),
        (BuildSystem.MESON, ["meson.build"]),
        (BuildSystem.MAKE, ["Makefile", "GNUmakefile", "makefile"]),
    ]

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self.build_system: BuildSystem = self._detect()
        self.has_devcontainer: bool = (repo_path / ".devcontainer").exists() or (
            repo_path / ".devcontainer.json"
        ).exists()
        self.has_project_dockerfile: bool = (repo_path / "Dockerfile").exists()
        self.compiler: str = self._detect_compiler()
        self.is_clang: bool = "clang" in self.compiler.lower()
        self.compile_commands: list[dict] | None = self._load_compile_commands()

    def _detect(self) -> BuildSystem:
        for build_system, files in self.INDICATORS:
            for filename in files:
                if (self.repo_path / filename).exists():
                    return build_system
        return BuildSystem.UNKNOWN

    def _load_compile_commands(self) -> list[dict] | None:
        import json
        for path in ["compile_commands.json", "build/compile_commands.json"]:
            cc_path = self.repo_path / path
            if cc_path.exists():
                try:
                    return json.loads(cc_path.read_text())
                except Exception:
                    pass
        return None

    def get_file_metadata(self, file_path: str) -> dict[str, str]:
        """Extract exact compiler and optimization flags for a specific file."""
        if not self.compile_commands:
            return {"compiler": self.compiler, "opt_level": "-O1", "flags": []}
            
        for cmd in self.compile_commands:
            if file_path in cmd.get("file", "") or file_path in cmd.get("command", ""):
                full_cmd = cmd.get("command", "")
                parts = full_cmd.split()
                compiler = parts[0]
                flags = [p for p in parts[1:] if p.startswith("-")]
                
                # Extract optimization level
                opt_level = "-O1"
                for f in flags:
                    if f in ("-O0", "-O1", "-O2", "-O3", "-Os", "-Oz"):
                        opt_level = f
                
                return {
                    "compiler": compiler,
                    "opt_level": opt_level,
                    "flags": _sanitize_flags(flags)
                }
        return {"compiler": self.compiler, "opt_level": "-O1", "flags": []}

    def _detect_compiler(self) -> str:
        """Check CMake cache or environment for the active compiler."""
        cmake_cache = self.repo_path / "build" / "CMakeCache.txt"
        if cmake_cache.exists():
            for line in cmake_cache.read_text().splitlines():
                if "CMAKE_CXX_COMPILER:FILEPATH" in line:
                    return line.split("=")[-1].strip()
        return os.environ.get("CXX", "c++")

    def sandbox_compiler_flags(self) -> dict[str, str]:
        """
        Returns the compiler and flags to use in the sandbox.
        Always enforces Clang for LibFuzzer compatibility.
        """
        base_flags = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
        if not self.is_clang:
            # Clang-Override: force clang++ even if project uses GCC
            return {
                "compiler": "clang++",
                "flags": base_flags,
                "override_reason": f"Project uses {self.compiler}; forced Clang for LibFuzzer/ASan support.",
            }
        return {"compiler": self.compiler, "flags": base_flags, "override_reason": ""}

    def hash_function_content(self, content: str) -> str:
        """SHA-256 hash of a function's source text (for incremental CPG)."""
        return hashlib.sha256(content.encode()).hexdigest()
