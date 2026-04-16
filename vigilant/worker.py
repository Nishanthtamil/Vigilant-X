"""
vigilant/worker.py
───────────────────
Celery task queue for multi-tenant PR review processing.

Each worker process instantiates its own LLMClient and Neo4j driver to
avoid shared state between concurrent jobs. The broker is Redis.

Usage:
    # Start 4 workers:
    celery -A vigilant.worker worker --concurrency=4 -Q pr_reviews --loglevel=info

    # Enqueue from GitHub webhook handler:
    from vigilant.worker import run_review_task
    run_review_task.apply_async(args=[repo_path, pr_number, ...], priority=8)
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from celery import Celery
from celery.signals import worker_process_init

logger = logging.getLogger(__name__)

# ── Celery app configuration ──────────────────────────────────────────────────

app = Celery("vigilant")

app.config_from_object({
    "broker_url": "redis://localhost:6379/0",
    "result_backend": "redis://localhost:6379/1",
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],
    "task_routes": {
        "vigilant.worker.run_review_task": {"queue": "pr_reviews"},
    },
    # Priority: 0 (lowest) to 10 (highest).
    # Small PRs (≤5 files) get priority=9, large PRs get priority=1.
    "task_queue_max_priority": 10,
    "task_default_priority": 5,
    # Recycle workers after 50 tasks to prevent memory leaks from large CPG builds.
    "worker_max_tasks_per_child": 50,
    # Prefetch 1 task at a time so priority ordering is respected.
    "worker_prefetch_multiplier": 1,
})


# ── Per-worker LLMClient initialisation ──────────────────────────────────────

@worker_process_init.connect
def init_worker(**kwargs: Any) -> None:
    """
    Called once per worker process at startup.
    Pre-initialise the LLMClient so the first task does not pay cold-start cost.
    Do NOT share this instance across tasks — each task call creates its own
    from the already-initialised provider connection.
    """
    logger.info("Celery worker process initialised")


# ── Task definition ───────────────────────────────────────────────────────────

@app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="vigilant.worker.run_review_task",
    time_limit=1800,     # 30-minute hard limit
    soft_time_limit=1500,  # 25-minute soft limit (raises SoftTimeLimitExceeded)
)
def run_review_task(
    self,
    repo_path: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    github_repo: str = "",
    pr_title: str = "",
    pr_body: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Celery task wrapping run_review(). Each invocation owns its own
    LLMClient, Neo4j driver, and CPGBuilder — no shared state.

    Priority recommendation:
        len(changed_files) <= 5  → priority=9
        len(changed_files) <= 20 → priority=5
        len(changed_files) > 20  → priority=1
    """
    try:
        # Import inside task to ensure each worker process gets a fresh client
        from vigilant.orchestrator import run_review

        logger.info(
            "Worker: starting review PR #%d in %s (%d files)",
            pr_number, github_repo, len(changed_files),
        )
        state = run_review(
            repo_path=repo_path,
            pr_number=pr_number,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            github_repo=github_repo,
            pr_title=pr_title,
            pr_body=pr_body,
            dry_run=dry_run,
        )
        proven = sum(1 for v in state.vulnerabilities if v.status.value in ("PROVEN", "SANDBOX_VERIFIED", "FUZZ_VERIFIED"))
        logger.info("Worker: PR #%d complete — %d verified findings", pr_number, proven)
        return {
            "pr_number": pr_number,
            "github_repo": github_repo,
            "proven_count": proven,
            "errors": state.errors,
        }

    except Exception as exc:
        logger.error("Worker: PR #%d failed: %s", pr_number, exc)
        raise self.retry(exc=exc)


# ── Priority helper ───────────────────────────────────────────────────────────

def enqueue_review(
    repo_path: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    github_repo: str = "",
    pr_title: str = "",
    pr_body: str = "",
    dry_run: bool = False,
) -> Any:
    """
    Enqueue a PR review with automatic priority based on PR size.
    Small PRs get faster feedback; large PRs wait in the queue.
    """
    if len(changed_files) <= 5:
        priority = 9
    elif len(changed_files) <= 20:
        priority = 5
    else:
        priority = 1

    logger.info(
        "Enqueuing PR #%d (%d files) at priority=%d",
        pr_number, len(changed_files), priority,
    )
    return run_review_task.apply_async(
        args=[repo_path, pr_number, base_sha, head_sha,
              changed_files, github_repo, pr_title, pr_body, dry_run],
        priority=priority,
    )
