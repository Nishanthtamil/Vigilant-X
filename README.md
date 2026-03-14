# Vigilant-X 🔍

> **Agentic C++ security reviewer with formal verification and sandboxed proof-of-concept analysis.**

Vigilant-X goes far beyond static analysis. It traces data flow **across file boundaries**, formally proves vulnerabilities with **Z3**, falls back to **LibFuzzer** for black-box paths, runs crashes in a **Docker + LLVM Sanitizers sandbox**, and posts a Gold Standard report back to the PR.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         VIGILANT-X PIPELINE                             │
│                                                                         │
│  ┌────────────────┐   ┌─────────────────┐   ┌──────────────────────┐  │
│  │  PLANE I       │   │  PLANE II       │   │  PLANE III           │  │
│  │  Ingestion     │──▶│  Analysis       │──▶│  Validation          │  │
│  │                │   │                 │   │                      │  │
│  │ • Joern CPG    │   │ • TaintTracker  │   │ • PoCGenerator       │  │
│  │ • Incremental  │   │   (APOC Neo4j)  │   │   (GoogleTest LLM)   │  │
│  │   SHA-256 hash │   │ • ConcolicEngine│   │ • SandboxRunner      │  │
│  │ • IntentParser │   │   Phase1: Z3    │   │   (Docker+Clang)     │  │
│  │   (LLM)        │   │   Phase2: Fuzz  │   │   ASan/TSan/MSan     │  │
│  └────────────────┘   └─────────────────┘   └──────────────────────┘  │
│                                                         │              │
│                                         ┌───────────────┘              │
│                                         ▼                              │
│                              ┌──────────────────────┐                  │
│                              │  PLANE IV            │                  │
│                              │  Communication       │                  │
│                              │ • Reviewer (LLM)     │                  │
│                              │ • PRCommenter        │                  │
│                              │   (GitHub)           │                  │
│                              └──────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/nishanth/Vigilant-X.git
cd Vigilant-X
pip install -e ".[dev]"
```

### 2. Configure

```bash
cp .env.example .env
# Fill in: GROQ_API_KEY, NEO4J_AURA_PASSWORD (or leave USE_LOCAL_NEO4J=true)
```

### 3. Start Local Neo4j

```bash
docker-compose up neo4j -d
# Wait ~15s for Neo4j to become healthy
```

### 4. Dry-run on the Example Vulnerable Code

```bash
vigilant-x review \
  --repo examples/vuln_sample \
  --pr-number 0 \
  --dry-run
```

Expected output: a Z3-proven heap-buffer-overflow with a `std::span`-based C++20 fix.

### 5. Run Unit Tests

```bash
pytest tests/ -m "not integration" -v
```

### 6. Run Integration Tests (requires Docker + Clang)

```bash
docker-compose build sandbox-build
pytest tests/ -m integration -v
```

---

## GitHub Actions Integration

Add the following secret to your repository: `GROQ_API_KEY`.

The bundled workflow (`.github/workflows/vigilant_x.yml`) triggers automatically on every Pull Request. It:
1. Starts a Neo4j service container.
2. Installs Vigilant-X.
3. Runs the full 4-plane analysis.
4. Posts a verified report as a PR comment.
5. Exits with code **1** if any verified vulnerability is found (blocks merge).

---

## Code Law Rules

Edit `code_law/default_rules.yaml` to customise what Vigilant-X checks.

| Severity | Effect |
|---|---|
| `CRITICAL` | Full pipeline: Z3 → LibFuzzer → Sandbox → PR comment |
| `ADVISORY` | LLM review only — sandbox not invoked |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Orchestration | Python 3.12 + LangGraph |
| LLM (testing) | Groq — `meta-llama/llama-4-scout-17b-16e-instruct` |
| LLM (production) | OpenAI GPT-4o / Anthropic Claude 3.5 Sonnet |
| CPG | Joern → Neo4j (APOC path-finding) |
| Formal Verification | Z3 SMT Solver |
| Grey-box Fuzzing | LLVM LibFuzzer |
| Dynamic Analysis | Docker + Clang ASan / TSan / MSan / UBSan |
| PR Integration | PyGithub |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `groq` | Active LLM provider: `groq`, `openai`, `anthropic` |
| `GROQ_API_KEY` | — | Groq API key |
| `GROQ_MODEL` | `meta-llama/llama-4-scout-17b-16e-instruct` | Groq model |
| `USE_LOCAL_NEO4J` | `true` | Use docker-compose Neo4j instead of Aura |
| `Z3_MEMORY_LIMIT_MB` | `2048` | Z3 solver memory cap (prevents OOM) |
| `SANDBOX_TIMEOUT_SECONDS` | `120` | Docker sandbox timeout |
| `LIBFUZZER_TIMEOUT_SECONDS` | `60` | LibFuzzer run duration |
| `GITHUB_TOKEN` | — | GitHub PAT for posting PR comments |

---

## License

MIT
