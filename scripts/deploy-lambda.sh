#!/bin/bash
# Deploy Lambda functions (package + create/update)
# Usage: ./deploy-lambda.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ===== Config =====
REGION="${REGION:-us-east-1}"           # Default region
EVIDENCE_BUCKET="${EVIDENCE_BUCKET:?Please set EVIDENCE_BUCKET environment variable}"
SCANNER_ROLE_ARN="${SCANNER_ROLE_ARN:?Set the Lambda IAM role ARN for scanner}"
REMEDIATION_ROLE_ARN="${REMEDIATION_ROLE_ARN:?Set the Lambda IAM role ARN for remediation}"

echo "Deploying Lambda functions to region $REGION..."
echo "Using evidence bucket: $EVIDENCE_BUCKET"

cd "$PROJECT_DIR/lambda"

# Create a temporary virtualenv to isolate dependencies
rm -rf venv_tmp
python3 -m venv venv_tmp
source venv_tmp/bin/activate
pip install --upgrade pip

package_lambda() {
    FUNC_NAME=$1
    FILE_NAME=$2

    echo "Packaging $FUNC_NAME..."
    rm -rf ${FUNC_NAME}_package ${FUNC_NAME}.zip
    mkdir -p ${FUNC_NAME}_package

    # Install dependencies into the package folder
    pip install -r requirements.txt -t ${FUNC_NAME}_package/ -q

    # Copy lambda code
    cp $FILE_NAME ${FUNC_NAME}_package/

    # Create zip
    cd ${FUNC_NAME}_package
    zip -r ../${FUNC_NAME}.zip . -q
    cd ..
    rm -rf ${FUNC_NAME}_package
}

# Package functions
package_lambda "scanner" "scanner.py"
package_lambda "remediation" "remediation.py"

# Deploy function to AWS Lambda
deploy_lambda() {
    FUNC_NAME=$1
    ZIP_FILE=$2
    ROLE_ARN=$3
    HANDLER=$4

    echo "Deploying $FUNC_NAME to AWS Lambda..."
    
    if aws lambda get-function --function-name "$FUNC_NAME" --region "$REGION" >/dev/null 2>&1; then
        # Update existing function
        aws lambda update-function-code \
            --function-name "$FUNC_NAME" \
            --zip-file "fileb://$ZIP_FILE" \
            --region "$REGION"

        aws lambda update-function-configuration \
            --function-name "$FUNC_NAME" \
            --role "$ROLE_ARN" \
            --handler "$HANDLER" \
            --environment "Variables={EVIDENCE_BUCKET=$EVIDENCE_BUCKET}" \
            --region "$REGION"
    else
        # Create new function
        aws lambda create-function \
            --function-name "$FUNC_NAME" \
            --runtime python3.10 \
            --role "$ROLE_ARN" \
            --handler "$HANDLER" \
            --zip-file "fileb://$ZIP_FILE" \
            --environment "Variables={EVIDENCE_BUCKET=$EVIDENCE_BUCKET}" \
            --region "$REGION"
    fi
}

# Deploy both Lambda functions
deploy_lambda "scanner" "scanner.zip" "$SCANNER_ROLE_ARN" "scanner.lambda_handler"
deploy_lambda "remediation" "remediation.zip" "$REMEDIATION_ROLE_ARN" "remediation.lambda_handler"

# Cleanup
deactivate
rm -rf venv_tmp

echo "Lambda functions deployed successfully!"
aws lambda list-functions --region "$REGION"
