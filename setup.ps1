# Vigilant-X Windows Setup Script
# ───────────────────────────────

Write-Host "🔍 Starting Vigilant-X setup for Windows..." -ForegroundColor Cyan

# 1. Check/Install Java (Required for Joern)
try {
    java -version 2>$null
    Write-Host "✅ Java is already installed." -ForegroundColor Green
} catch {
    Write-Host "☕ Java not found. Attempting to install OpenJDK 17 via winget..." -ForegroundColor Yellow
    winget install Microsoft.OpenJDK.17
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install Java. Please install Java 17+ manually from https://adoptium.net/" -ForegroundColor Red
        exit 1
    }
}

# 2. Setup Python Environment
Write-Host "🐍 Setting up Python environment..." -ForegroundColor Cyan
if (!(Test-Path ".venv")) {
    python -m venv .venv
}
& .\.venv\Scripts\Activate.ps1
python -m pip install -q --upgrade pip
python -m pip install -q -e ".[dev]"

# 3. Install Joern locally if not found
if (!(Get-Command joern -ErrorAction SilentlyContinue) -and !(Test-Path "joern\joern.bat")) {
    Write-Host "🛠️ Joern not found. Downloading local copy..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path "joern_tmp" | Out-Null
    Invoke-WebRequest -Uri "https://github.com/joernio/joern/releases/latest/download/joern-cli.zip" -OutFile "joern-cli.zip"
    Expand-Archive -Path "joern-cli.zip" -DestinationPath "joern_tmp" -Force
    Move-Item -Path "joern_tmp\joern-cli\*" -Destination "joern" -Force
    Remove-Item -Recurse -Force "joern_tmp", "joern-cli.zip"
    Write-Host "✅ Joern installed to $(Get-Location)\joern" -ForegroundColor Green
}

# 4. Setup .env
if (!(Test-Path ".env")) {
    Write-Host "📝 Creating .env from .env.example..." -ForegroundColor Cyan
    Copy-Item ".env.example" ".env"
    $groq_key = Read-Host "🔑 Enter your GROQ_API_KEY (or press Enter to skip)"
    if ($groq_key) {
        (Get-Content .env) -replace 'your_groq_api_key_here', $groq_key | Set-Content .env
    }
}

# 5. Infrastructure Check
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "🐳 Starting Neo4j via Docker..." -ForegroundColor Cyan
    docker compose up neo4j -d
} else {
    Write-Host "⚠️ Docker not found. You'll need it to run the analysis infrastructure." -ForegroundColor Yellow
}

Write-Host "`n✨ Setup complete!" -ForegroundColor Green
Write-Host "🚀 To start, run: .\.venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "💡 Then run: vigilant-x review --repo examples\vulnerable.py --pr-number 0 --dry-run" -ForegroundColor Gray
