#!/bin/bash
set -e

# Vigilant-X Setup Script
# ───────────────────────
# This script automates the installation of dependencies, 
# including Joern and the Docker-based analysis engine.

echo "🔍 Starting Vigilant-X setup..."

# 1. Check and Install Java (required by Joern)
install_java() {
    echo "☕ Java not found. Attempting to install OpenJDK 17..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y openjdk-17-jre-headless
    elif command -v brew &> /dev/null; then
        brew install openjdk@17
    elif command -v yum &> /dev/null; then
        sudo yum install -y java-17-openjdk
    else
        echo "❌ Could not find a supported package manager (apt, brew, yum). Please install Java 17+ manually."
        exit 1
    fi
}

if ! command -v java &> /dev/null; then
    install_java
else
    # Quick check for version >= 11
    JAVA_VER=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}' | cut -d. -f1)
    # Handle version format like "1.8.0" vs "17.0.1"
    if [ "$JAVA_VER" = "1" ]; then
        JAVA_VER=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}' | cut -d. -f2)
    fi
    
    if [ "$JAVA_VER" -lt 11 ]; then
        echo "⚠️ Java version is too old ($JAVA_VER). Joern requires Java 11+ (17 recommended)."
        install_java
    else
        echo "✅ Java version $JAVA_VER is already available."
    fi
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
