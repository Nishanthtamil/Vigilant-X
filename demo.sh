#!/bin/bash
set -e

# Vigilant-X Demo Script
# ──────────────────────
# Runs a local security review on the provided vulnerable examples.

echo "🚀 Starting Vigilant-X demo..."

# 1. Activate venv if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# 2. Check for dependencies
if ! command -v vigilant-x &> /dev/null; then
    echo "❌ vigilant-x CLI not found. Please run ./setup.sh first."
    exit 1
fi

# 3. Check for Neo4j
echo "🔍 Checking infrastructure..."
if ! docker ps | grep -q "vigilant-neo4j"; then
    echo "⚠️ Neo4j container not running. Attempting to start..."
    docker-compose up neo4j -d
    # Wait for Neo4j to be ready
    echo "⏳ Waiting for Neo4j to be ready..."
    sleep 5
fi

# 4. Run the review
echo "🔍 Analyzing examples/vulnerable.py..."
vigilant-x review --repo . --pr-number 0 --dry-run

echo "✨ Demo complete!"
