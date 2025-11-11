#!/bin/bash
# Destroy infrastructure
# Usage: ./scripts/destroy.sh [environment]

set -e

ENVIRONMENT=${1:-dev}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "⚠️  WARNING: This will destroy all resources in environment: $ENVIRONMENT"
read -p "Are you sure? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

cd "$PROJECT_DIR/terraform"

echo "🗑️  Destroying infrastructure..."
terraform destroy -var="environment=$ENVIRONMENT" -auto-approve

echo "✅ Infrastructure destroyed"
