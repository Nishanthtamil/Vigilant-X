"""
vigilant/ingestion/framework_detector.py
──────────────────────────────────────────
Detects web frameworks from package manifests and injects framework-specific
taint sinks and safe-pattern whitelists into the TaintTracker.

This is the primary mechanism for framework-aware analysis — the difference
between flagging Django's safe ORM filter() calls and correctly identifying
only the dangerous raw() and extra() injection patterns.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Framework-specific sink definitions ───────────────────────────────────────
# Each entry: framework_name → {sinks: [...], safe_patterns: [...]}

FRAMEWORK_PROFILES: dict[str, dict[str, list[str]]] = {
    "django": {
        "sinks": ["raw", "extra", "RawSQL", "render_to_string", "execute"],
        "safe_patterns": ["filter", "exclude", "get", "create", "update", "delete",
                          "annotate", "aggregate", "values", "values_list"],
        "description": "Django ORM injection and template sinks",
    },
    "flask": {
        "sinks": ["render_template_string", "make_response", "send_file",
                  "redirect", "Markup"],
        "safe_patterns": ["render_template", "jsonify", "abort"],
        "description": "Flask XSS and open-redirect sinks",
    },
    "fastapi": {
        "sinks": ["HTMLResponse", "StreamingResponse", "FileResponse"],
        "safe_patterns": ["JSONResponse", "Response"],
        "description": "FastAPI response injection sinks",
    },
    "express": {
        "sinks": ["send", "render", "set", "redirect", "sendFile",
                  "exec", "execSync", "spawn", "spawnSync"],
        "safe_patterns": ["json", "sendStatus", "end"],
        "description": "Express.js XSS and command injection sinks",
    },
    "nextjs": {
        "sinks": ["dangerouslySetInnerHTML", "eval", "Function"],
        "safe_patterns": ["createElement", "cloneElement"],
        "description": "Next.js/React injection sinks",
    },
    "spring": {
        "sinks": ["query", "update", "execute", "Runtime.exec",
                  "ProcessBuilder.start", "ScriptEngine.eval"],
        "safe_patterns": ["queryForObject", "queryForList"],
        "description": "Spring JDBC injection and RCE sinks",
    },
    "rails": {
        "sinks": ["find_by_sql", "execute", "connection.execute",
                  "send_file", "send_data", "render"],
        "safe_patterns": ["where", "find", "find_by", "create", "update"],
        "description": "Rails ActiveRecord injection sinks",
    },
    "laravel": {
        "sinks": ["DB::select", "DB::statement", "exec", "shell_exec",
                  "system", "passthru", "eval"],
        "safe_patterns": ["DB::table", "Model::where", "Model::find"],
        "description": "Laravel query injection and RCE sinks",
    },
    "gin": {
        "sinks": ["c.String", "c.Data", "exec.Command"],
        "safe_patterns": ["c.JSON", "c.XML", "c.Status"],
        "description": "Gin (Go) XSS and command injection sinks",
    },
}

# ── Manifest detection signals ─────────────────────────────────────────────────

_DETECTION_RULES: list[tuple[str, str, str]] = [
    # (framework_name, manifest_file, signal_string)
    ("django",   "requirements.txt",   "django"),
    ("django",   "requirements.txt",   "Django"),
    ("flask",    "requirements.txt",   "flask"),
    ("flask",    "requirements.txt",   "Flask"),
    ("fastapi",  "requirements.txt",   "fastapi"),
    ("express",  "package.json",       '"express"'),
    ("nextjs",   "package.json",       '"next"'),
    ("nextjs",   "package.json",       '"Next"'),
    ("spring",   "pom.xml",            "spring-boot"),
    ("spring",   "pom.xml",            "spring-webmvc"),
    ("spring",   "build.gradle",       "spring-boot"),
    ("rails",    "Gemfile",            "rails"),
    ("rails",    "Gemfile",            "railties"),
    ("laravel",  "composer.json",      "laravel/framework"),
    ("gin",      "go.mod",             "gin-gonic/gin"),
]


class FrameworkDetector:
    """
    Detects frameworks present in a repository and returns the combined
    set of additional sinks and safe patterns to inject into TaintTracker.
    """

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self._detected: list[str] = []

    def detect(self) -> list[str]:
        """Return list of detected framework names."""
        if self._detected:
            return self._detected

        found: set[str] = set()
        for framework, manifest_file, signal in _DETECTION_RULES:
            manifest_path = self.repo_path / manifest_file
            if manifest_path.exists():
                try:
                    content = manifest_path.read_text(errors="replace").lower()
                    if signal.lower() in content:
                        found.add(framework)
                        logger.info(
                            "FrameworkDetector: detected %s via %s",
                            framework, manifest_file,
                        )
                except Exception:
                    continue

        self._detected = sorted(found)
        return self._detected

    def extra_sinks(self) -> list[str]:
        """Return all framework-specific sink function names detected."""
        sinks: list[str] = []
        for fw in self.detect():
            profile = FRAMEWORK_PROFILES.get(fw, {})
            sinks.extend(profile.get("sinks", []))
        return list(set(sinks))

    def safe_patterns(self) -> list[str]:
        """Return all safe patterns to whitelist from reporting."""
        patterns: list[str] = []
        for fw in self.detect():
            profile = FRAMEWORK_PROFILES.get(fw, {})
            patterns.extend(profile.get("safe_patterns", []))
        return list(set(patterns))

    def summary(self) -> str:
        detected = self.detect()
        if not detected:
            return "no frameworks detected"
        return f"detected: {', '.join(detected)}"
