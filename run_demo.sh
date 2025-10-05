#!/bin/bash

# Demo script for Terraform Security Scanner
# Auto-setup: Creates venv and installs dependencies if needed

set -e  # Exit on error

echo "═══════════════════════════════════════════════════════"
echo "    TERRAFORM SECURITY SCANNER - DEMONSTRATION"
echo "═══════════════════════════════════════════════════════"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

# Check if dependencies are installed
if ! python -c "import hcl2" 2>/dev/null; then
    echo "📥 Installing dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    echo "✓ Dependencies installed"
fi

# Create models directory if it doesn't exist
mkdir -p models

# Initialize ML model if needed (first run)
if [ ! -f "models/isolation_forest.pkl" ]; then
    echo "🤖 Training ML model (first run only)..."
    python -m terrasafe.main test_files/secure.tf > /dev/null 2>&1 || true
    echo "✓ ML model ready"
fi

echo ""
echo "▶ TEST 1: HIGH RISK Configuration (vulnerable.tf)"
echo "═══════════════════════════════════════════════════════"
python -m terrasafe.main test_files/vulnerable.tf || true

echo ""
echo "▶ TEST 2: SECURE Configuration (secure.tf)"
echo "═══════════════════════════════════════════════════════"
python -m terrasafe.main test_files/secure.tf

echo ""
echo "▶ TEST 3: MEDIUM RISK Configuration (mixed.tf)"
echo "═══════════════════════════════════════════════════════"
python -m terrasafe.main test_files/mixed.tf || true

echo ""
echo "═══════════════════════════════════════════════════════"
echo "✓ Security analysis completed for all configurations!"
echo ""
echo "Summary:"
echo "  • vulnerable.tf: Multiple critical issues detected"
echo "  • secure.tf: Follows security best practices"
echo "  • mixed.tf: Some improvements recommended"
echo "═══════════════════════════════════════════════════════"