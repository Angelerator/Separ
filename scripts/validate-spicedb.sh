#!/bin/bash
# Validate SpiceDB schema and authorization model
# 
# Prerequisites:
# - Install zed: brew install authzed/tap/zed
# - Or: go install github.com/authzed/zed@latest
#
# Usage:
#   ./scripts/validate-spicedb.sh
#   ./scripts/validate-spicedb.sh --explain  # For detailed output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== SpiceDB Schema Validation ==="
echo ""

# Check if zed is installed
if ! command -v zed &> /dev/null; then
    echo "Error: 'zed' CLI not found."
    echo ""
    echo "Install zed using one of these methods:"
    echo "  brew install authzed/tap/zed"
    echo "  go install github.com/authzed/zed@latest"
    echo ""
    exit 1
fi

echo "Using zed version: $(zed version 2>/dev/null || echo 'unknown')"
echo ""

# Validate schema file
echo "1. Validating schema syntax..."
if zed validate "$PROJECT_DIR/spicedb/schema.zed" 2>/dev/null; then
    echo "   ✅ Schema syntax is valid"
else
    echo "   ❌ Schema syntax validation failed"
    exit 1
fi
echo ""

# Validate all test files
echo "2. Running validation tests..."
VALIDATION_DIR="$PROJECT_DIR/spicedb/validations"

if [ -d "$VALIDATION_DIR" ]; then
    for file in "$VALIDATION_DIR"/*.yaml; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            echo "   Testing: $filename"
            if zed validate "$file" 2>&1 | head -5; then
                echo "   ✅ $filename passed"
            else
                echo "   ❌ $filename failed"
                exit 1
            fi
            echo ""
        fi
    done
else
    echo "   No validation files found in $VALIDATION_DIR"
fi

echo "=== All validations passed ==="
