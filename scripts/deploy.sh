#!/bin/bash
# Full deployment script cho AWS Compliance-as-Code (CloudTrail + S3)
# Usage: ./scripts/deploy.sh [environment]

set -e

ENVIRONMENT=${1:-dev}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🚀 Starting deployment for environment: $ENVIRONMENT"
echo "Project directory: $PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Kiểm tra prerequisites
log_info "Checking prerequisites..."

for cmd in terraform aws python3; do
    if ! command -v $cmd &>/dev/null; then
        log_error "$cmd not found. Please install it."
        exit 1
    fi
done

if ! aws sts get-caller-identity &>/dev/null; then
    log_error "AWS credentials not configured. Run 'aws configure'"
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region || echo "us-east-1")

log_info "AWS Account: $AWS_ACCOUNT_ID"
log_info "AWS Region: $AWS_REGION"

# 2. Deploy CloudTrail + S3 bằng Terraform
log_info "Deploying CloudTrail and S3 bucket via Terraform..."

cd "$PROJECT_DIR/iac/terraform/aws"

terraform init
terraform validate
terraform plan -var="environment=$ENVIRONMENT" -out=tfplan
terraform apply -auto-approve tfplan

# Lấy outputs
EVIDENCE_BUCKET=$(terraform output -raw evidence_bucket_name)
CLOUDTRAIL_NAME=$(terraform output -raw cloudtrail_name)

echo ""
log_info "=== Deployment Complete ==="
echo ""
echo "S3 Evidence Bucket: $EVIDENCE_BUCKET"
echo "CloudTrail Name: $CLOUDTRAIL_NAME"
echo ""
