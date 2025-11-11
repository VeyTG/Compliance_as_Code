# CloudTrail Configuration (CIS-AWS-3, CIS-AWS-4)

# ===== CloudTrail =====
# ✅ CIS-AWS-3: Enabled in all regions
# ✅ CIS-AWS-4: Log validation enabled

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true # ✅ CIS-AWS-3: All regions
  enable_log_file_validation    = true # ✅ CIS-AWS-4: Log validation

  # CloudWatch Logs integration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # Event selector: Log all management events
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Log data events cho S3
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.evidence.id}/*"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]

  tags = merge(local.common_tags, {
    Name       = "Main CloudTrail"
    Compliance = "CIS-AWS-3 CIS-AWS-4"
  })
}

# CloudWatch Log Group cho CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name_prefix}"
  retention_in_days = 7 # Free tier

  tags = merge(local.common_tags, {
    Name = "CloudTrail Logs"
  })
}

# IAM Role cho CloudTrail -> CloudWatch
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${local.name_prefix}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

# IAM Policy cho CloudTrail -> CloudWatch
resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${local.name_prefix}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}
