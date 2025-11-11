# EventBridge Configuration
# Schedule Lambda scanner to run periodically

# ===== EventBridge Rule =====
resource "aws_cloudwatch_event_rule" "compliance_scan" {
  name                = "${local.name_prefix}-compliance-scan"
  description         = "Trigger compliance scanner on schedule"
  schedule_expression = var.scan_schedule # rate(1 hour)

  tags = merge(local.common_tags, {
    Name = "Compliance Scan Schedule"
  })
}

