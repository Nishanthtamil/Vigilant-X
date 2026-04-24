# Vigilant-X Windows Demo Script
# ───────────────────────────────

Write-Host "🚀 Starting Vigilant-X demo..." -ForegroundColor Cyan

# 1. Activate venv if it exists
if (Test-Path ".venv\Scripts\Activate.ps1") {
    & .\.venv\Scripts\Activate.ps1
}

# 2. Check for dependencies
if (!(Get-Command vigilant-x -ErrorAction SilentlyContinue)) {
    Write-Host "❌ vigilant-x CLI not found. Please run .\setup.ps1 first." -ForegroundColor Red
    exit 1
}

# 3. Check for Neo4j
Write-Host "🔍 Checking infrastructure..." -ForegroundColor Cyan
if (Get-Command docker -ErrorAction SilentlyContinue) {
    if (!(docker ps | Select-String "vigilant-neo4j")) {
        Write-Host "⚠️ Neo4j container not running. Attempting to start..." -ForegroundColor Yellow
        docker compose up neo4j -d
        Start-Sleep -Seconds 5
    }
}

# 4. Run the review
Write-Host "🔍 Analyzing examples\vulnerable.py..." -ForegroundColor Cyan
vigilant-x review --repo . --pr-number 0 --dry-run

Write-Host "`n✨ Demo complete!" -ForegroundColor Green
