| Control ID       | Loại Kiểm Tra                 | Kiểm Tra IaC (Checkov)| Kiểm Tra Runtime (InSpec/Ansible)  | Cơ Chế Thực Thi          |
|------------------|--------------------------------|-----------------------|------------------------------------|--------------------------|
| CIS-AWS-3        | CloudTrail Enabled All Regions | CKV_AWS_144           | aws_cloudtrail_trail.enabled       | AWS Config / Lambda      |
| CIS-AWS-4        | CloudTrail Log Validation      | CKV_AWS_145 (custom)  | aws_cloudtrail_trail.log_validation| AWS Config / Lambda      |
| CIS-AWS-5        | S3 Buckets Not Public          | CKV_AWS_18            | aws_s3_bucket.should_not_be_public | Cloud Custodian / Lambda |
| CIS-AWS-6        | S3 Encryption Enabled          | CKV_AWS_19            | aws_s3_bucket.encrypted            | Cloud Custodian / Lambda |
