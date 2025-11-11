"""
AWS Compliance Remediation Lambda Function
Tự động sửa các compliance violations
"""

import json
import boto3
import os
from datetime import datetime
from typing import Dict, List, Any

# AWS clients
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
cloudtrail_client = boto3.client('cloudtrail')
sns_client = boto3.client('sns')

# Environment variables
EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')


def lambda_handler(event, context):
    """
    Main handler - remediate violations
    """
    print(f"Starting remediation at {datetime.now().isoformat()}")
    print(f"Event: {json.dumps(event)}")

    # Parse violations từ event
    violations = event if isinstance(event, list) else []

    remediation_results = []

    for violation in violations:
        try:
            result = remediate_violation(violation)
            remediation_results.append(result)
        except Exception as e:
            print(f"Error remediating {violation.get('resource')}: {str(e)}")
            remediation_results.append({
                'resource': violation.get('resource'),
                'control': violation.get('control'),
                'status': 'failed',
                'error': str(e)
            })

    # Save remediation log
    save_remediation_log(remediation_results)

    # Send notification
    send_notification(remediation_results)

    print(f"Remediation complete. Processed: {len(remediation_results)}")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'total_remediated': len(remediation_results),
            'successful': len([r for r in remediation_results if r['status'] == 'success']),
            'failed': len([r for r in remediation_results if r['status'] == 'failed']),
            'results': remediation_results
        })
    }


def remediate_violation(violation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remediate một violation dựa trên fix type
    """
    fix_type = violation.get('fix')
    resource = violation.get('resource')
    control = violation.get('control')

    print(f"Remediating {control}: {resource} with fix: {fix_type}")

    # Dispatch tới remediation function tương ứng
    remediation_map = {
        'enable_public_block': fix_s3_public_access,
        'enable_encryption': fix_s3_encryption,
        'remove_ssh_rule': fix_security_group_ssh,
        'remove_rdp_rule': fix_security_group_rdp,
        'restrict_default_sg': fix_default_security_group,
        'enable_flow_logs': fix_vpc_flow_logs,
        'enable_multi_region_trail': fix_cloudtrail_multi_region,
        'enable_log_validation': fix_cloudtrail_log_validation
    }

    fix_function = remediation_map.get(fix_type)

    if not fix_function:
        return {
            'resource': resource,
            'control': control,
            'status': 'skipped',
            'message': f'No remediation function for: {fix_type}'
        }

    try:
        fix_function(violation)
        return {
            'resource': resource,
            'control': control,
            'status': 'success',
            'message': f'Successfully applied fix: {fix_type}'
        }
    except Exception as e:
        raise Exception(f"Remediation failed: {str(e)}")


# ===== S3 Remediation Functions =====

def fix_s3_public_access(violation: Dict[str, Any]):
    """
    CIS-AWS-5: Block S3 public access
    """
    bucket_name = violation['resource']

    print(f"Blocking public access for bucket: {bucket_name}")

    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'BlockPublicPolicy': True,
            'IgnorePublicAcls': True,
            'RestrictPublicBuckets': True
        }
    )

    print(f"✅ Successfully blocked public access for {bucket_name}")


def fix_s3_encryption(violation: Dict[str, Any]):
    """
    CIS-AWS-6: Enable S3 encryption
    """
    bucket_name = violation['resource']

    print(f"Enabling encryption for bucket: {bucket_name}")

    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    },
                    'BucketKeyEnabled': True
                }
            ]
        }
    )

    print(f"✅ Successfully enabled encryption for {bucket_name}")


# ===== Security Group Remediation Functions =====

def fix_security_group_ssh(violation: Dict[str, Any]):
    """
    CIS-AWS-7: Remove SSH from 0.0.0.0/0
    """
    sg_id = violation['resource']
    rule_detail = violation.get('rule_detail', {})

    print(f"Removing SSH rule from security group: {sg_id}")

    ec2_client.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            'FromPort': 22,
            'ToPort': 22,
            'IpProtocol': 'tcp',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )

    print(f"✅ Successfully removed SSH rule from {sg_id}")


def fix_security_group_rdp(violation: Dict[str, Any]):
    """
    CIS-AWS-8: Remove RDP from 0.0.0.0/0
    """
    sg_id = violation['resource']

    print(f"Removing RDP rule from security group: {sg_id}")

    ec2_client.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            'FromPort': 3389,
            'ToPort': 3389,
            'IpProtocol': 'tcp',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )

    print(f"✅ Successfully removed RDP rule from {sg_id}")


def fix_default_security_group(violation: Dict[str, Any]):
    """
    CIS-AWS-9: Restrict default security group
    """
    sg_id = violation['resource']

    print(f"Restricting default security group: {sg_id}")

    # Get current rules
    sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]

    # Remove all ingress rules
    if sg['IpPermissions']:
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=sg['IpPermissions']
        )

    # Remove all egress rules
    if sg['IpPermissionsEgress']:
        ec2_client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=sg['IpPermissionsEgress']
        )

    print(f"✅ Successfully restricted default SG {sg_id}")


# ===== VPC Remediation Functions =====

def fix_vpc_flow_logs(violation: Dict[str, Any]):
    """
    CIS-AWS-10: Enable VPC flow logs
    """
    vpc_id = violation['resource']

    print(f"Enabling flow logs for VPC: {vpc_id}")

    # Create CloudWatch log group
    logs_client = boto3.client('logs')
    log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"

    try:
        logs_client.create_log_group(logGroupName=log_group_name)
        logs_client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=7
        )
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass

    # Create IAM role for flow logs (nếu chưa có)
    # Note: Trong production, role nên được tạo sẵn
    iam_client = boto3.client('iam')
    role_name = 'VPCFlowLogsRole'

    try:
        role = iam_client.get_role(RoleName=role_name)
        role_arn = role['Role']['Arn']
    except iam_client.exceptions.NoSuchEntityException:
        # Tạo role mới
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            })
        )
        role_arn = role['Role']['Arn']

        # Attach policy
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='VPCFlowLogsPolicy',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams"
                    ],
                    "Resource": "*"
                }]
            })
        )

    # Create flow log
    ec2_client.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs',
        LogGroupName=log_group_name,
        DeliverLogsPermissionArn=role_arn
    )

    print(f"✅ Successfully enabled flow logs for {vpc_id}")


# ===== CloudTrail Remediation Functions =====

def fix_cloudtrail_multi_region(violation: Dict[str, Any]):
    """
    CIS-AWS-3: Enable CloudTrail in all regions
    """
    trail_name = violation['resource']
    trail_arn = violation.get('resource_arn')

    print(f"Enabling multi-region for CloudTrail: {trail_name}")

    cloudtrail_client.update_trail(
        Name=trail_name,
        IsMultiRegionTrail=True
    )

    print(f"✅ Successfully enabled multi-region for {trail_name}")


def fix_cloudtrail_log_validation(violation: Dict[str, Any]):
    """
    CIS-AWS-4: Enable CloudTrail log validation
    """
    trail_name = violation['resource']

    print(f"Enabling log validation for CloudTrail: {trail_name}")

    cloudtrail_client.update_trail(
        Name=trail_name,
        EnableLogFileValidation=True
    )

    print(f"✅ Successfully enabled log validation for {trail_name}")


# ===== Helper Functions =====

def save_remediation_log(results: List[Dict[str, Any]]):
    """
    Lưu remediation log vào S3
    """
    try:
        timestamp = datetime.now().isoformat()
        filename = f"remediation/{timestamp}.json"

        s3_client.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=filename,
            Body=json.dumps({
                'timestamp': timestamp,
                'environment': ENVIRONMENT,
                'total_remediated': len(results),
                'results': results
            }, indent=2),
            ContentType='application/json'
        )

        print(f"Remediation log saved to s3://{EVIDENCE_BUCKET}/{filename}")

    except Exception as e:
        print(f"Error saving remediation log: {str(e)}")


def send_notification(results: List[Dict[str, Any]]):
    """
    Gửi notification về remediation results
    """
    try:
        successful = len([r for r in results if r['status'] == 'success'])
        failed = len([r for r in results if r['status'] == 'failed'])

        message = f"""
AWS Compliance Remediation Report

Environment: {ENVIRONMENT}
Timestamp: {datetime.now().isoformat()}

Total Remediated: {len(results)}
- Successful: {successful}
- Failed: {failed}

Results:
{json.dumps(results, indent=2)}

Evidence bucket: s3://{EVIDENCE_BUCKET}/remediation/
"""

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[AWS Compliance] Remediation Complete - {successful}/{len(results)} successful",
            Message=message
        )
        print("Remediation notification sent via SNS")

    except Exception as e:
        print(f"Error sending notification: {str(e)}")
