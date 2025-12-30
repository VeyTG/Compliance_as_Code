# S3 Buckets Configuration
# Bao gồm cả compliant và non-compliant examples để demo

# ===== COMPLIANT BUCKET: Evidence Storage =====
resource "aws_s3_bucket" "evidence" {
  bucket = "${var.evidence_bucket_name}-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "Compliance Evidence Bucket"
    Compliance  = "CIS-AWS-5 CIS-AWS-6"
    Description = "Luu tru scan results và evidence"
  })
}

# CIS-AWS-5: Block public access
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CIS-AWS-6: Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ===== COMPLIANT BUCKET: CloudTrail Logs =====
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.cloudtrail_bucket_name}-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "CloudTrail Logs Bucket"
    Compliance  = "CIS-AWS-3 CIS-AWS-4"
    Description = "Luu tru CloudTrail logs"
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# CloudTrail bucket policy
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ===== NON-COMPLIANT BUCKET: Test Purpose =====
# Bucket này để demo violations và auto-remediation
resource "aws_s3_bucket" "test_non_compliant" {
  bucket = "test-non-compliant-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "Non-Compliant Test Bucket"
    Compliance  = "VIOLATION"
    Description = "Bucket để test scanner và remediation"
  })
}

# ❌ VIOLATION CIS-AWS-5: Public access allowed
resource "aws_s3_bucket_public_access_block" "test_non_compliant" {
  bucket = aws_s3_bucket.test_non_compliant.id

  block_public_acls       = true # ❌ Vi phạm!
  block_public_policy     = true # ❌ Vi phạm!
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ❌ VIOLATION CIS-AWS-6: No encryption
# (Không tạo encryption config = không có encryption)
