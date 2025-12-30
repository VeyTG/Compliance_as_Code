# S3 Buckets Configuration
# Bao gồm cả compliant và non-compliant examples để demo

# ===== BUCKET CHUYÊN DỤNG ĐỂ LƯU ACCESS LOGS =====
resource "aws_s3_bucket" "access_logs" {
  bucket        = "compliance-access-logs-${random_id.suffix.hex}"
  force_destroy = true # Để dễ destroy khi test

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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.arn
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.arn
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.arn
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
  block_public_acls       = false # ← Đổi thành false để demo public access violation
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Thêm encryption để CKV_AWS_19 PASS (nếu muốn compliant hoàn toàn)
resource "aws_s3_bucket_server_side_encryption_configuration" "test_non_compliant" {
  bucket = aws_s3_bucket.test_non_compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.arn
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

# Thêm KMS Key cho encryption (SSE-KMS thay vì AES256)
resource "aws_kms_key" "s3_kms" {
  description         = "KMS key for S3 encryption - Compliance"
  enable_key_rotation = true

  tags = merge(local.common_tags, {
    Name = "S3 Compliance KMS Key"
  })
}

resource "aws_kms_alias" "s3_kms" {
  name          = "alias/s3-compliance-key"
  target_key_id = aws_kms_key.s3_kms.key_id
}


# Bucket replica ở region khác (ví dụ us-west-2)
resource "aws_s3_bucket" "cloudtrail_replica" {
  provider = aws.replica
  bucket   = "${var.cloudtrail_bucket_name}-replica-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name        = "CloudTrail Logs Bucket Replica"
    Compliance  = "CIS-AWS-3"
    Description = "Replica của CloudTrail logs bucket"
  })
}

resource "aws_s3_bucket_versioning" "cloudtrail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.cloudtrail_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.cloudtrail_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.arn
    }
  }
}

# Thêm provider replica (vào variables.tf hoặc main.tf)
provider "aws" {
  alias  = "replica"
  region = "us-west-2" # Region khác
}

# IAM Role cho S3 Replication
resource "aws_iam_role" "replication_role" {
  name = "s3-replication-role-compliance"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "replication_policy" {
  name = "compliance-s3-replication-policy"
  role = aws_iam_role.replication_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cloudtrail.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = [
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:PutObjectTagging"
        ]
        Resource = [
          "${aws_s3_bucket.cloudtrail_replica.arn}/*"
        ]
      }
    ]
  })
}

# Bật replication
resource "aws_s3_bucket_replication_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  role   = aws_iam_role.replication_role.arn

  rule {
    id       = "cloudtrail-full-replication"
    status   = "Enabled"
    priority = 1

    destination {
      bucket        = aws_s3_bucket.cloudtrail_replica.arn
      storage_class = "STANDARD"

      access_control_translation {
        owner = "Destination"
      }

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.s3_kms.arn
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    filter {
      prefix = ""
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail]
}
