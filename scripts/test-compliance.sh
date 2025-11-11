#!/bin/bash
# Test compliance policies
# Usage: ./scripts/test-compliance.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🧪 Testing Compliance Policies..."

# Test OPA policies
echo ""
echo "1. Testing OPA policies..."
cd "$PROJECT_DIR/policies/rego"
opa test . -v

# Test Terraform
echo ""
echo "2. Validating Terraform..."
cd "$PROJECT_DIR/terraform"
terraform init -backend=false
terraform validate
terraform fmt -check -recursive || true

# Test Python
echo ""
echo "3. Testing Python syntax..."
cd "$PROJECT_DIR/lambda"
python3 -m py_compile scanner.py
python3 -m py_compile remediation.py

cd "$PROJECT_DIR/dashboard"
python3 -m py_compile app.py

echo ""
echo "✅ All tests passed!"
