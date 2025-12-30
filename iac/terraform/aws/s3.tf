# S3 Buckets Configuration
# Bao gồm cả compliant và non-compliant examples để demo

# ===== BUCKET CHUYÊN DỤNG ĐỂ LƯU ACCESS LOGS =====
resource "aws_s3_bucket" "access_logs" {
  bucket        = "compliance-access-logs-${random_id.suffix.hex}"
  force_destroy = true  # Để dễ destroy khi test

  tags = merge(local.common_tags, {
    Name        = "S3 Access Logs Bucket"
    Description = "Lưu trữ access logs của các S3 bucket khác"
    Compliance  = "CIS-AWS-5"
  })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ===== COMPLIANT BUCKET: Evidence Storage =====
resource "aws_s3_bucket" "evidence" {
  bucket = "${var.evidence_bucket_name}-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "Compliance Evidence Bucket"
    Compliance  = "CIS-AWS-5 CIS-AWS-6"
    Description = "Lưu trữ scan results và evidence"
  })
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Bật access logging cho bucket evidence (CIS-AWS-5)
resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence-logs/"
}

# ===== COMPLIANT BUCKET: CloudTrail Logs =====
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.cloudtrail_bucket_name}-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "CloudTrail Logs Bucket"
    Compliance  = "CIS-AWS-3 CIS-AWS-4"
    Description = "Lưu trữ CloudTrail logs"
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
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

# Bật access logging cho bucket cloudtrail
resource "aws_s3_bucket_logging" "cloudtrail" {
  bucket        = aws_s3_bucket.cloudtrail.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudtrail-logs/"
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

# ===== NON-COMPLIANT BUCKET: Test Purpose (sẽ dùng để demo violation) =====
resource "aws_s3_bucket" "test_non_compliant" {
  bucket = "test-non-compliant-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "Non-Compliant Test Bucket"
    Compliance  = "VIOLATION"
    Description = "Bucket để test scanner và remediation"
  })
}

# Để demo violation: bạn có thể tạm đổi các giá trị này thành false
resource "aws_s3_bucket_public_access_block" "test_non_compliant" {
  bucket                  = aws_s3_bucket.test_non_compliant.id
  block_public_acls       = false   # ← Đổi thành false để demo public access violation
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Thêm encryption để CKV_AWS_19 PASS (nếu muốn compliant hoàn toàn)
resource "aws_s3_bucket_server_side_encryption_configuration" "test_non_compliant" {
  bucket = aws_s3_bucket.test_non_compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Thêm versioning
resource "aws_s3_bucket_versioning" "test_non_compliant" {
  bucket = aws_s3_bucket.test_non_compliant.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Bật access logging cho bucket test_non_compliant
resource "aws_s3_bucket_logging" "test_non_compliant" {
  bucket        = aws_s3_bucket.test_non_compliant.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "test-non-compliant-logs/"
}
