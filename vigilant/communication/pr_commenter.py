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
        Post the report markdown as a PR comment.

        Args:
            report: The ReviewReport to post.
            dry_run: If True, print the comment instead of posting it.

        Returns:
            The report, with posted_comment_url filled in (or dry_run URL).
        """
        if dry_run:
            from rich.console import Console
            from rich.markdown import Markdown
            console = Console()
            console.rule("[bold blue]Vigilant-X Dry-Run Report")
            console.print(Markdown(report.markdown_body))
            report.posted_comment_url = "dry-run://no-post"
            return report

        if not self.settings.github_token:
            logger.error("PRCommenter: GITHUB_TOKEN not set. Cannot post comment.")
            return report

        try:
            from github import Github   # type: ignore[import]
            g = Github(self.settings.github_token)
            repo = g.get_repo(report.github_repo)
            pr = repo.get_pull(report.pr_number)

            # Delete existing Vigilant-X bot comments (avoid spam on re-run)
            for old_comment in pr.get_issue_comments():
                if "Vigilant-X" in old_comment.body:
                    old_comment.delete()
                    logger.info("PRCommenter: removed old Vigilant-X comment")

            comment = pr.create_issue_comment(report.markdown_body)
            report.posted_comment_url = comment.html_url
            logger.info("PRCommenter: posted review to %s", comment.html_url)

        except Exception as e:
            logger.error("PRCommenter: failed to post comment: %s", e)

        return report
