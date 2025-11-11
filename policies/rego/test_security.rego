# OPA Test Cases cho Security Policies

package aws.compliance

# ===== Test CIS-AWS-5: S3 Public Access =====

test_s3_public_access_blocked {
    not deny[_] with input as {
        "resource_changes": [{
            "type": "aws_s3_bucket_public_access_block",
            "address": "aws_s3_bucket_public_access_block.test",
            "change": {
                "after": {
                    "block_public_acls": true,
                    "block_public_policy": true
                }
            }
        }]
    }
}

test_s3_public_access_violation {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "type": "aws_s3_bucket_public_access_block",
            "address": "aws_s3_bucket_public_access_block.test",
            "change": {
                "after": {
                    "block_public_acls": false,
                    "block_public_policy": false
                }
            }
        }]
    }
}

# ===== Test CIS-AWS-7: SSH from Internet =====

test_ssh_restricted {
    not deny[_] with input as {
        "resource_changes": [{
            "type": "aws_security_group",
            "address": "aws_security_group.test",
            "change": {
                "after": {
                    "ingress": [{
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/8"]
                    }]
                }
            }
        }]
    }
}

test_ssh_from_internet_violation {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "type": "aws_security_group",
            "address": "aws_security_group.test",
            "change": {
                "after": {
                    "ingress": [{
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }
}

# ===== Test CIS-AWS-8: RDP from Internet =====

test_rdp_from_internet_violation {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "type": "aws_security_group",
            "address": "aws_security_group.test",
            "change": {
                "after": {
                    "ingress": [{
                        "from_port": 3389,
                        "to_port": 3389,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }
}

# ===== Test CIS-AWS-10: VPC Flow Logs =====

test_vpc_flow_logs_enabled {
    not deny[_] with input as {
        "resource_changes": [
            {
                "type": "aws_vpc",
                "address": "aws_vpc.main",
                "change": {
                    "after": {
                        "id": "vpc-123"
                    }
                }
            },
            {
                "type": "aws_flow_log",
                "address": "aws_flow_log.main",
                "change": {
                    "after": {
                        "vpc_id": "vpc-123"
                    }
                }
            }
        ]
    }
}
