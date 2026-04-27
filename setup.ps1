# ==============================================================================
# FIX 1: Set the working directory to the script's location immediately
# ==============================================================================
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $PSScriptRoot

Write-Host " Starting Vigilant-X setup for Windows..." -ForegroundColor Cyan

# 1. Check/Install Java (Required for Joern)
try {
    java -version 2>$null
    Write-Host " Java is already installed." -ForegroundColor Green
} catch {
    Write-Host " Java not found. Attempting to install OpenJDK 17 via winget..." -ForegroundColor Yellow
    winget install Microsoft.OpenJDK.17
    if ($LASTEXITCODE -ne 0) {
        Write-Host " Failed to install Java. Please install Java 17+ manually from https://adoptium.net/" -ForegroundColor Red
        exit 1
    }
}

# 2. Setup Python Environment
Write-Host " Setting up Python environment..." -ForegroundColor Cyan
if (!(Test-Path ".venv")) {
    python -m venv .venv
}
& .\.venv\Scripts\Activate.ps1

# Removed -q (quiet) so you can see the progress/errors
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

# 3. Install/Locate Joern
$JoernInstalled = Get-Command joern -ErrorAction SilentlyContinue

if (!$JoernInstalled -and !(Test-Path "joern\joern-cli\joern.bat") -and !(Test-Path "joern\joern.bat")) {
    Write-Host "Joern not found. Checking for local files..." -ForegroundColor Yellow
    
    $LocalJoern = Get-ChildItem -Filter "joern.bat" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($LocalJoern) {
        Write-Host "Found Joern at: $($LocalJoern.FullName)" -ForegroundColor Green
    } else {
        Write-Host "Downloading local Joern copy..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Force -Path "joern_tmp" | Out-Null
        Invoke-WebRequest -Uri "https://github.com/joernio/joern/releases/latest/download/joern-cli.zip" -OutFile "joern-cli.zip"
        Expand-Archive -Path "joern-cli.zip" -DestinationPath "joern_tmp" -Force
        
        if (Test-Path "joern_tmp\joern-cli") {
            Move-Item -Path "joern_tmp\joern-cli" -Destination "joern" -Force
        }
        
        Remove-Item -Recurse -Force "joern_tmp", "joern-cli.zip"
        Write-Host " Joern installed to $PSScriptRoot\joern" -ForegroundColor Green
    }
} else {
    Write-Host " Joern is already configured." -ForegroundColor Green
}

# 4. Setup .env
# ==============================================================================
# FIX 2: Using $PSScriptRoot for ALL file operations to avoid C:\Users\acer errors
# ==============================================================================
$ExampleEnv = Join-Path $PSScriptRoot ".env.example"
$TargetEnv = Join-Path $PSScriptRoot ".env"

if (!(Test-Path $TargetEnv)) {
    Write-Host "Creating .env from .env.example..." -ForegroundColor Cyan
    if (Test-Path $ExampleEnv) {
        Copy-Item $ExampleEnv $TargetEnv -Force
        Write-Host " Successfully created .env" -ForegroundColor Green
        
        $groq_key = Read-Host " Enter your GROQ_API_KEY (or press Enter to skip)"
        if ($groq_key) {
            # Use absolute path for Get-Content/Set-Content
            (Get-Content $TargetEnv) -replace 'your_groq_api_key_here', $groq_key | Set-Content $TargetEnv
            Write-Host " API Key updated." -ForegroundColor Green
        }
    } else {
        Write-Host " Error: .env.example not found in $PSScriptRoot" -ForegroundColor Red
    }
}

# 5. Infrastructure Check
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host " Starting Neo4j via Docker..." -ForegroundColor Cyan
    docker compose up neo4j -d
} else {
    Write-Host " Docker not found. You'll need it to run the analysis infrastructure." -ForegroundColor Yellow
}

# ==============================================================================
# FIX 3: Removed special characters/emojis to prevent encoding "Terminator" errors
# ==============================================================================
Write-Host "`n Setup complete!" -ForegroundColor Green
Write-Host " To start, run: .\.venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host " Then run: vigilant-x review --repo examples\vulnerable.py --pr-number 0 --dry-run" -ForegroundColor Gray