# Terraform Outputs

output "evidence_bucket_name" {
  description = "Tên S3 bucket chứa compliance evidence"
  value       = aws_s3_bucket.evidence.id
}

output "cloudtrail_bucket_name" {
  description = "Tên S3 bucket chứa CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail.id
}

output "eventbridge_rule_name" {
  description = "EventBridge rule name"
  value       = aws_cloudwatch_event_rule.compliance_scan.name
}
