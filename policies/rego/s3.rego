package main

deny contains msg if {
    input.resource_changes[_].type == "aws_s3_bucket"
    input.resource_changes[_].change.after.acl == "public-read"
    msg := "S3 bucket must not be public-read"
}
