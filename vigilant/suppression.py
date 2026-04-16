"""vigilant/suppression.py — Load and apply .vigilant-x-ignore suppression rules."""
from __future__ import annotations
import logging
from pathlib import Path
from vigilant.models import Vulnerability

logger = logging.getLogger(__name__)
IGNORE_FILE = ".vigilant-x-ignore"

def load_suppressions(repo_path: Path) -> set[tuple[str, int, str]]:
    """
    Read .vigilant-x-ignore. Each non-comment line has format:
        relative/path/to/file.cpp:LINE_NUMBER:rule_id
    Returns a set of (file_path, line_number, rule_id) tuples.
    LINE_NUMBER = 0 means suppress all findings for that rule in that file.
    """
    ignore_file = repo_path / IGNORE_FILE
    suppressions: set[tuple[str, int, str]] = set()
    if not ignore_file.exists():
        return suppressions
    for line in ignore_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            logger.warning("Suppression: malformed line: %s", line)
            continue
        file_path = parts[0].strip()
        try:
            line_number = int(parts[1].strip())
        except ValueError:
            logger.warning("Suppression: invalid line number in: %s — skipping", line)
            continue
        rule_id = parts[2].strip()
        suppressions.add((file_path, line_number, rule_id))
    return suppressions

def apply_suppressions(
    vulns: list[Vulnerability],
    suppressions: set[tuple[str, int, str]],
) -> list[Vulnerability]:
    """Return only vulns that are not covered by a suppression rule."""
    if not suppressions:
        return vulns
    kept = []
    for v in vulns:
        p = v.taint_path
        rule = p.rule_id or ""
        file_ = p.sink.file_path
        line = p.sink.line_number
        if (file_, line, rule) in suppressions:
            logger.info("Suppressed: %s:%d [%s]", file_, line, rule)
            continue
        if (file_, 0, rule) in suppressions:
            logger.info("Suppressed (all lines): %s [%s]", file_, rule)
            continue
        kept.append(v)
    return kept
