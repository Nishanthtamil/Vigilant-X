"""
vigilant/ingestion/intent_parser.py
─────────────────────────────────────
LLM agent that reads PR context (title, body, README, linked Jira ticket)
and produces a PRIntent: the "Why" behind the code change.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from vigilant.llm_client import LLMClient
from vigilant.models import PRContext, PRIntent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior C++ architect performing a security-focused code review.
Your task is to analyze a Pull Request and extract structured intent.

You will be given:
- The PR title and description
- The list of changed files
- (Optionally) the project README and any Jira/issue ticket content

Return a JSON object with the following fields:
{
  "purpose": "<one-sentence description of what this PR does>",
  "changed_modules": ["<module1>", "<module2>"],
  "risk_areas": ["<risk1>", "<risk2>"],
  "code_law_violations_suspected": ["<rule_id1>", "<rule_id2>"]
}

Risk areas should include memory safety, authentication, threading, or any domain-specific risks.
Only include code_law_violations_suspected if you strongly suspect them based on the PR description.
Return ONLY the JSON object, no explanation."""


class IntentParser:
    """Parses PR context into a structured PRIntent using an LLM."""

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    def parse(self, pr_context: PRContext, readme_path: Path | None = None) -> PRIntent:
        """
        Analyze the PR context and return a PRIntent.

        Args:
            pr_context: The PR metadata (title, body, changed files).
            readme_path: Optional path to the project README for extra context.
        """
        user_prompt = self._build_prompt(pr_context, readme_path)
        logger.info("IntentParser: analyzing PR #%d", pr_context.pr_number)

        raw = self.llm.ask(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1,
            max_tokens=1024,
        )

        return self._parse_response(raw)

    def _build_prompt(self, pr_context: PRContext, readme_path: Path | None) -> str:
        parts = [
            f"## PR #{pr_context.pr_number}: {pr_context.pr_title}",
            "",
            "### Description",
            pr_context.pr_body or "(No description provided)",
            "",
            "### Changed Files",
        ]
        for f in pr_context.changed_files[:50]:  # cap at 50 files
            parts.append(f"  - {f}")

        if readme_path and readme_path.exists():
            readme = readme_path.read_text(errors="replace")[:2000]  # first 2k chars
            parts += ["", "### Project README (excerpt)", readme]

        # Try to extract Jira ticket URL from PR body
        jira_tickets = self._extract_jira_tickets(pr_context.pr_body)
        if jira_tickets:
            parts += ["", f"### Linked Jira Tickets: {', '.join(jira_tickets)}"]

        return "\n".join(parts)

    @staticmethod
    def _extract_jira_tickets(body: str) -> list[str]:
        """Extract Jira ticket IDs like PROJ-1234 from PR body."""
        if not body:
            return []
        return re.findall(r"\b[A-Z][A-Z0-9]+-\d+\b", body)

    @staticmethod
    def _parse_response(raw: str) -> PRIntent:
        """Parse the LLM's JSON response into a PRIntent."""
        import json

        # Strip any markdown fences the LLM might add
        raw = re.sub(r"```(?:json)?", "", raw).strip().strip("`")

        try:
            data = json.loads(raw)
            return PRIntent(
                purpose=data.get("purpose", ""),
                changed_modules=data.get("changed_modules", []),
                risk_areas=data.get("risk_areas", []),
                code_law_violations_suspected=data.get("code_law_violations_suspected", []),
            )
        except json.JSONDecodeError:
            logger.warning("IntentParser: could not parse LLM response as JSON, using defaults.")
            return PRIntent(purpose=raw[:200] if raw else "Unknown purpose")
