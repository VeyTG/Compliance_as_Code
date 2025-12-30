# Terraform Variables

variable "aws_region" {
  description = "AWS region để deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "evidence_bucket_name" {
  description = "Tên S3 bucket lưu evidence"
  type        = string
  default     = "compliance-evidence"
}

variable "cloudtrail_bucket_name" {
  description = "Tên S3 bucket cho CloudTrail logs"
  type        = string
  default     = "compliance-cloudtrail"
}

variable "scan_schedule" {
  description = "EventBridge schedule expression"
  type        = string
  default     = "rate(1 hour)"
}

variable "notification_email" {
  description = "Email nhận thông báo compliance violations"
  type        = string
  default     = "security@example.com"
}

variable "allowed_ssh_cidr" {
  description = "CIDR blocks được phép SSH (compliant example)"
  type        = list(string)
  default     = ["10.0.0.0/8"] # Internal only
}

variable "vpc_cidr" {
  description = "CIDR block cho VPC"
  type        = string
  default     = "10.0.0.0/16"
}

locals {
  common_tags = {
    Project     = "AWS-Compliance"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}
