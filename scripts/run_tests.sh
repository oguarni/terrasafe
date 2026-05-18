#!/bin/bash
# TerraVault Test Runner
# This script ensures tests run in a clean environment

set -e

echo "=========================================="
echo "TerraVault Test Suite Runner"
echo "=========================================="
echo ""

# Unset the API key hash to prevent shell expansion corruption
unset TERRAVAULT_API_KEY_HASH

echo "✓ Environment cleaned (TERRAVAULT_API_KEY_HASH unset)"
echo ""
echo "Running pytest..."
echo ""

# Run pytest with proper environment
env -u TERRAVAULT_API_KEY_HASH python3 -m pytest "$@"

exit_code=$?

echo ""
if [ $exit_code -eq 0 ]; then
    echo "=========================================="
    echo "✓ All tests passed!"
    echo "=========================================="
else
    echo "=========================================="
    echo "✗ Some tests failed (exit code: $exit_code)"
    echo "=========================================="
fi

exit $exit_code
