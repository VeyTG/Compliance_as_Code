# AWS Compliance-as-Code Terraform Configuration
# Tạo infrastructure để demo CIS Benchmark compliance

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AWS-Compliance"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}

# Random suffix để tránh trùng tên
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "compliance-${var.environment}"
  common_tags = {
    Project     = "AWS-Compliance"
    Environment = var.environment
  }
}
