"""
vigilant/webhook/github_webhook.py
────────────────────────────────────
FastAPI webhook handler for GitHub PR comment events.

Handles:
  @vigilant/** explain <topic>      — explain a CWE or finding
  @vigilant/** generate-fix <file>  — generate a patch for a file
  @vigilant/** summarize            — post a plain-English summary of all findings
  @vigilant/** ignore <rule_id>     — add a suppression to .vigilant-x-ignore
  @vigilant/** help                 — list available commands

Mount in your existing FastAPI/Flask app or run standalone:
  uvicorn vigilant.webhook.github_webhook:app --port 8080
"""
from __future__ import annotations
import hashlib, hmac, logging, re
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from vigilant.config import get_settings
from vigilant.llm_client import LLMClient

logger = logging.getLogger(__name__)
app = FastAPI()

COMMAND_RE = re.compile(r" @vigilant/\*\*(?:-x)?\s+(?P<cmd>\S+)(?:\s+(?P<args>.+))?", re.I)

async def _handle_explain(args: str, payload: dict) -> None:
    llm = LLMClient()
    response = llm.ask(
        "You are a security educator. Explain the concept clearly and concisely.",
        f"Explain {args} in the context of secure code review. "
        f"Include: what it is, how it's exploited, and how to fix it. Max 200 words.",
        max_tokens=512,
    )
    await _post_reply(payload, response)

async def _handle_generate_fix(args: str, payload: dict) -> None:
    # Basic stub — in a real deployment this would pull the file content and call Reviewer
    await _post_reply(payload, f"Generating fix for `{args}`... (Note: this requires full repo access in the worker)")

async def _handle_summarize(args: str, payload: dict) -> None:
    await _post_reply(payload, "Summarizing findings... (Feature coming soon)")

async def _handle_ignore(args: str, payload: dict) -> None:
    await _post_reply(payload, f"Rule `{args}` added to ignore list. (Feature coming soon)")

async def _handle_help(args: str, payload: dict) -> None:
    msg = (
        "**Vigilant-X commands:**\n\n"
        "- ` @vigilant/** explain <CWE or topic>` — explain a vulnerability class\n"
        "- ` @vigilant/** generate-fix <file>` — propose a fix for a file\n"
        "- ` @vigilant/** summarize` — plain-English summary of all findings\n"
        "- ` @vigilant/** ignore <rule_id>` — add a suppression entry\n"
        "- ` @vigilant/** help` — show this message\n"
    )
    await _post_reply(payload, msg)

COMMANDS = {
    "explain":      _handle_explain,
    "generate-fix": _handle_generate_fix,
    "summarize":    _handle_summarize,
    "ignore":       _handle_ignore,
    "help":         _handle_help,
}

@app.post("/webhook/github")
async def github_webhook(request: Request, background: BackgroundTasks):
    body = await request.body()
    _verify_signature(body, request.headers.get("X-Hub-Signature-256", ""))
    payload = await request.json()
    event = request.headers.get("X-GitHub-Event", "")
    if event == "issue_comment" and payload.get("action") == "created":
        comment_body = payload["comment"]["body"]
        m = COMMAND_RE.search(comment_body)
        if m:
            background.add_task(_dispatch_command, m.group("cmd").lower(),
                                 m.group("args") or "", payload)
    return {"ok": True}

def _verify_signature(body: bytes, sig_header: str) -> None:
    secret = get_settings().github_webhook_secret.encode()
    if not secret:
        return
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

async def _dispatch_command(cmd: str, args: str, payload: dict) -> None:
    handler = COMMANDS.get(cmd)
    if handler:
        await handler(args, payload)
    else:
        await _post_reply(payload, f"Unknown command `{cmd}`. Try ` @vigilant/** help`.")

async def _post_reply(payload: dict, body: str) -> None:
    settings = get_settings()
    if not settings.github_token:
        logger.warning("GITHUB_TOKEN not set; cannot post reply")
        return
    try:
        from github import Github
        g = Github(settings.github_token)
        repo = g.get_repo(payload["repository"]["full_name"])
        issue_number = payload["issue"]["number"]
        repo.get_issue(issue_number).create_comment(body)
    except Exception as e:
        logger.error("Failed to post webhook reply: %s", e)
