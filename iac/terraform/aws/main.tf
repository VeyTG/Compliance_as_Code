provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "example" {
  bucket = "my-compliance-test-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "my-compliance-test-bucket"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
