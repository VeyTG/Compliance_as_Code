| Control ID         | Loại Kiểm Tra    | Kiểm Tra IaC (Checkov) | Kiểm Tra Runtime (InSpec/Ansible)  | Cơ Chế Thực Thi |
|--------------------|------------------|------------------------|------------------------------------|-----------------|
| CIS-AWS-2.1.5      | S3 Public        | CKV_AWS_18             | aws_s3_bucket.should_not be_public | Cloud Custodian |
| CIS-AWS-3.1        | CloudTrail       | CKV_AWS_144            | aws_cloudtrail_trail.enabled       | AWS Config      |
| ISO-27017-11.2.1   | S3 Encryption    | CKV_AWS_19             | aws_s3_bucket.encrypted            | Cloud Custodian |
| CIS-Linux-5.2.1    | SSH Root Login   | N/A                    | Ansible playbook                   | Ansible         |
