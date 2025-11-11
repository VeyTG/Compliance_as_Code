# OPA/Rego Policies cho AWS CIS Benchmark
# Kiểm tra Terraform plan cho compliance violations

package aws.compliance

# ===== HELPER FUNCTIONS =====

# Lấy tất cả resource changes
resource_changes[resource] {
    resource := input.resource_changes[_]
}

# Lấy resource theo type
resources_by_type[type] = resources {
    type := input.resource_changes[_].type
    resources := [r | r := input.resource_changes[_]; r.type == type]
}

# ===== CIS-AWS-5: S3 Buckets Not Public =====

# Deny S3 buckets với public access
deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_acls == false

    msg := {
        "control": "CIS-AWS-5",
        "severity": "CRITICAL",
        "resource": resource.address,
        "message": sprintf("S3 bucket public access not blocked: %s", [resource.address]),
        "remediation": "Set block_public_acls = true"
    }
}

deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_policy == false

    msg := {
        "control": "CIS-AWS-5",
        "severity": "CRITICAL",
        "resource": resource.address,
        "message": sprintf("S3 bucket public policy not blocked: %s", [resource.address]),
        "remediation": "Set block_public_policy = true"
    }
}

# ===== CIS-AWS-6: S3 Encryption Enabled =====

# Lấy danh sách S3 buckets
s3_buckets[bucket] {
    bucket := resource_changes[_]
    bucket.type == "aws_s3_bucket"
}

# Lấy danh sách buckets có encryption
encrypted_buckets[bucket_id] {
    resource := resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    bucket_id := resource.change.after.bucket
}

# Deny bucket không có encryption
deny[msg] {
    bucket := s3_buckets[_]
    bucket_id := bucket.change.after.bucket
    not encrypted_buckets[bucket_id]

    msg := {
        "control": "CIS-AWS-6",
        "severity": "HIGH",
        "resource": bucket.address,
        "message": sprintf("S3 bucket encryption not enabled: %s", [bucket.address]),
        "remediation": "Add aws_s3_bucket_server_side_encryption_configuration"
    }
}

# ===== CIS-AWS-7: No SSH from Internet =====

# Deny Security Groups với SSH từ 0.0.0.0/0
deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_security_group"

    ingress := resource.change.after.ingress[_]
    ingress.from_port == 22
    ingress.to_port == 22

    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := {
        "control": "CIS-AWS-7",
        "severity": "CRITICAL",
        "resource": resource.address,
        "message": sprintf("SSH (port 22) open to internet: %s", [resource.address]),
        "remediation": "Remove 0.0.0.0/0 from SSH ingress rules"
    }
}

# ===== CIS-AWS-8: No RDP from Internet =====

# Deny Security Groups với RDP từ 0.0.0.0/0
deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_security_group"

    ingress := resource.change.after.ingress[_]
    ingress.from_port == 3389
    ingress.to_port == 3389

    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := {
        "control": "CIS-AWS-8",
        "severity": "CRITICAL",
        "resource": resource.address,
        "message": sprintf("RDP (port 3389) open to internet: %s", [resource.address]),
        "remediation": "Remove 0.0.0.0/0 from RDP ingress rules"
    }
}

# ===== CIS-AWS-9: Default Security Group Restricted =====

# Deny default security groups với rules
deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_default_security_group"

    # Check if có ingress rules
    count(resource.change.after.ingress) > 0

    msg := {
        "control": "CIS-AWS-9",
        "severity": "HIGH",
        "resource": resource.address,
        "message": sprintf("Default security group has ingress rules: %s", [resource.address]),
        "remediation": "Remove all ingress rules from default security group"
    }
}

deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_default_security_group"

    # Check if có egress rules
    count(resource.change.after.egress) > 0

    msg := {
        "control": "CIS-AWS-9",
        "severity": "HIGH",
        "resource": resource.address,
        "message": sprintf("Default security group has egress rules: %s", [resource.address]),
        "remediation": "Remove all egress rules from default security group"
    }
}

# ===== CIS-AWS-10: VPC Flow Logs Enabled =====

# Lấy danh sách VPCs
vpcs[vpc] {
    vpc := resource_changes[_]
    vpc.type == "aws_vpc"
}

# Lấy VPCs có flow logs
vpcs_with_flow_logs[vpc_id] {
    resource := resource_changes[_]
    resource.type == "aws_flow_log"
    vpc_id := resource.change.after.vpc_id
}

# Deny VPC không có flow logs
deny[msg] {
    vpc := vpcs[_]
    vpc_id := vpc.change.after.id
    not vpcs_with_flow_logs[vpc_id]

    msg := {
        "control": "CIS-AWS-10",
        "severity": "MEDIUM",
        "resource": vpc.address,
        "message": sprintf("VPC flow logs not enabled: %s", [vpc.address]),
        "remediation": "Add aws_flow_log resource"
    }
}

# ===== CIS-AWS-3: CloudTrail Enabled All Regions =====

# Check CloudTrail multi-region
deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.after.is_multi_region_trail == false

    msg := {
        "control": "CIS-AWS-3",
        "severity": "HIGH",
        "resource": resource.address,
        "message": sprintf("CloudTrail not enabled in all regions: %s", [resource.address]),
        "remediation": "Set is_multi_region_trail = true"
    }
}

# ===== CIS-AWS-4: CloudTrail Log Validation =====

# Check CloudTrail log validation
deny[msg] {
    resource := resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.after.enable_log_file_validation == false

    msg := {
        "control": "CIS-AWS-4",
        "severity": "HIGH",
        "resource": resource.address,
        "message": sprintf("CloudTrail log validation not enabled: %s", [resource.address]),
        "remediation": "Set enable_log_file_validation = true"
    }
}

# ===== SUMMARY =====

# Count violations by severity
violation_count_critical := count([v | v := deny[_]; v.severity == "CRITICAL"])
violation_count_high := count([v | v := deny[_]; v.severity == "HIGH"])
violation_count_medium := count([v | v := deny[_]; v.severity == "MEDIUM"])
violation_count_total := count(deny)

# Compliance score (0-100)
compliance_score := score {
    total_checks := 10
    violations := violation_count_total
    score := round((1 - (violations / total_checks)) * 100)
}

# Summary object
summary := {
    "total_violations": violation_count_total,
    "critical": violation_count_critical,
    "high": violation_count_high,
    "medium": violation_count_medium,
    "compliance_score": compliance_score,
    "passed": violation_count_total == 0
}
