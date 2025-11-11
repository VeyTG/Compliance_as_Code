resource "aws_lambda_function" "scanner" {
  function_name = "scanner"
  runtime       = "python3.10"
  handler       = "scanner.lambda_handler"
  role          = aws_iam_role.lambda_scanner.arn

  source_code_hash = filebase64sha256("/home/deployer1/NT524/DOAN/Compliance_as_Code/lambda/scanner.zip")
  filename         = "/home/deployer1/NT524/DOAN/Compliance_as_Code/lambda/scanner.zip"

  environment {
    variables = {
      EVIDENCE_BUCKET = var.evidence_bucket_name
    }
  }

  tags = {
    Environment = "dev"
    Project     = "AWS-Compliance"
  }
}

resource "aws_lambda_function" "remediation" {
  function_name = "remediation"
  runtime       = "python3.10"
  handler       = "remediation.lambda_handler"
  role          = aws_iam_role.lambda_scanner.arn

  source_code_hash = filebase64sha256("/home/deployer1/NT524/DOAN/Compliance_as_Code/lambda/remediation.zip")
  filename         = "/home/deployer1/NT524/DOAN/Compliance_as_Code/lambda/remediation.zip"


  environment {
    variables = {
      EVIDENCE_BUCKET = var.evidence_bucket_name
    }
  }

  tags = {
    Environment = "dev"
    Project     = "AWS-Compliance"
  }
}

