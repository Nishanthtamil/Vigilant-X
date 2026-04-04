"""
vigilant/communication/pr_commenter.py
────────────────────────────────────────
Posts the ReviewReport as a GitHub PR review comment using PyGithub.
"""

from __future__ import annotations

import logging

from vigilant.config import get_settings
from vigilant.models import ReviewReport

logger = logging.getLogger(__name__)


class PRCommenter:
    """Posts Vigilant-X findings to a GitHub Pull Request."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def post(self, report: ReviewReport, dry_run: bool = False) -> ReviewReport:
        """
        Post the report as a single GitHub PR Review with inline comments.
        """
        if dry_run:
            from rich.console import Console
            from rich.markdown import Markdown
            console = Console()
            console.rule("[bold blue]Vigilant-X Dry-Run Review")
            console.print(Markdown(report.markdown_body))
            for vuln_id, fix in report.fixes.items():
                if fix.suggestion:
                    console.print(f"\n[bold green]Suggestion for {fix.file_path}:{fix.line_start}-{fix.line_end}:")
                    console.print(fix.suggestion)
            report.posted_comment_url = "dry-run://no-post"
            return report

        if not self.settings.github_token:
            logger.error("PRCommenter: GITHUB_TOKEN not set. Cannot post review.")
            return report

        try:
            from github import Github   # type: ignore[import]
            g = Github(self.settings.github_token)
            repo = g.get_repo(report.github_repo)
            pr = repo.get_pull(report.pr_number)

            # 1. Post summary review (body only, no inline comments via create_review)
            review = pr.create_review(
                body=report.markdown_body,
                event="COMMENT",
            )

            # 2. Post each inline comment individually
            for vuln in report.vulnerabilities:
                fix = report.fixes.get(vuln.vuln_id)
                if not fix or not fix.file_path or not fix.line_end:
                    continue
                
                body = f"### 🔴 Vigilant-X: {vuln.summary}\n\n"
                if fix.description:
                    body += fix.description[:3800]
                
                # If we have a suggestion, wrap it in a suggestion block if not already there
                if fix.suggestion and "```suggestion" not in body:
                    body += f"\n\n```suggestion\n{fix.suggestion}\n```"

                try:
                    pr.create_review_comment(
                        body=body,
                        commit=repo.get_commit(report.head_sha),
                        path=fix.file_path,
                        line=fix.line_end,
                    )
                except Exception as comment_err:
                    logger.warning(
                        "PRCommenter: could not post inline comment for %s: %s",
                        fix.file_path, comment_err,
                    )

            logger.info("PRCommenter: posted review and individual inline comments")
            report.posted_comment_url = f"https://github.com/{report.github_repo}/pull/{report.pr_number}/files"

        except Exception as e:
            logger.error("PRCommenter: failed to post review: %s", e)

        return report
