#!/bin/bash
set -e

# Vigilant-X Setup Script
# ───────────────────────
# This script automates the installation of dependencies, 
# including Joern and the Docker-based analysis engine.

echo "🔍 Starting Vigilant-X setup..."

# 1. Check for Java (required by Joern)
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Joern requires Java 17+. Please install it first."
    exit 1
fi

# 2. Setup Python environment
echo "🐍 Setting up Python environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[dev]"

# 3. Install Joern locally if not found
if ! command -v joern &> /dev/null && [ ! -f "./joern/joern" ]; then
    echo "🛠️ Joern not found on PATH. Installing local copy in ./joern..."
    mkdir -p joern
    wget -q https://github.com/joernio/joern/releases/latest/download/joern-cli.zip -O joern-cli.zip
    unzip -q joern-cli.zip -d joern_tmp
    mv joern_tmp/joern-cli/* joern/
    rm -rf joern_tmp joern-cli.zip
    echo "✅ Joern installed to $(pwd)/joern"
else
    echo "✅ Joern is already available."
fi

# 4. Setup .env
if [ ! -f ".env" ]; then
    echo "📝 Creating .env from .env.example..."
    cp .env.example .env
    
    # Prompt for GROQ_API_KEY (optional but recommended)
    read -p "🔑 Enter your GROQ_API_KEY (or press Enter to skip): " groq_key
    if [ ! -z "$groq_key" ]; then
        sed -i "s/your_groq_api_key_here/$groq_key/" .env
    fi
    echo "✅ .env created. Please review it to add other keys (GITHUB_TOKEN, etc.)."
else
    echo "✅ .env file already exists."
fi

# 5. Start Infrastructure (Neo4j)
if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    DOCKER_CMD="docker compose"
    if ! docker compose version &> /dev/null; then DOCKER_CMD="docker-compose"; fi
    
    echo "🐳 Starting Neo4j via $DOCKER_CMD..."
    $DOCKER_CMD up neo4j -d
    
    echo "🔨 Build the sandbox image? (This is slow but required for full PoC verification) [y/N]"
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "⏳ Building sandbox image (Stage: toolchain + sandbox)..."
        $DOCKER_CMD up sandbox-build
    fi
else
    echo "⚠️ Docker Compose not found. You'll need it to run Neo4j and the Sandbox."
fi

echo "✨ Setup complete!"
echo "🚀 Run 'source .venv/bin/activate' and then 'vigilant-x --help' to get started."
echo "💡 To run a demo: vigilant-x review --repo examples/vulnerable.py --pr-number 0 --dry-run"
