"""
AWS Compliance Scanner Lambda Function
Scan AWS resources theo CIS Benchmark và lưu violations vào S3
"""

import json
import boto3
import os
from datetime import datetime
from typing import Dict, List, Any

# AWS clients
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')
cloudtrail_client = boto3.client('cloudtrail')
cloudwatch_client = boto3.client('cloudwatch')

# Environment variables
EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')


def lambda_handler(event, context):
    """
    Main handler - scan tất cả CIS controls + EC2 instances
    """
    print(f"Starting compliance scan at {datetime.now().isoformat()}")
    print(f"Event: {json.dumps(event)}")

    violations = []

    try:
        violations.extend(scan_iam_controls())
        violations.extend(scan_cloudtrail_controls())
        violations.extend(scan_s3_controls())
        violations.extend(scan_security_group_controls())
        violations.extend(scan_vpc_controls())
        violations.extend(scan_ec2_instances())
    except Exception as e:
        print(f"Error during scan: {str(e)}")

    # Save results
    save_scan_results(violations)

    # Publish metrics
    publish_metrics(violations)

    print(f"Scan complete. Total violations: {len(violations)}")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'total_violations': len(violations),
            'critical': len([v for v in violations if v['severity'] == 'CRITICAL']),
            'high': len([v for v in violations if v['severity'] == 'HIGH']),
            'medium': len([v for v in violations if v['severity'] == 'MEDIUM']),
            'violations': violations
        })
    }


# ---- Scan Functions ----

def scan_iam_controls() -> List[Dict[str, Any]]:
    violations = []
    try:
        summary = iam_client.get_account_summary()
        if summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
            violations.append({
                'control': 'CIS-AWS-1',
                'resource': 'root-account',
                'severity': 'CRITICAL',
                'message': 'Root account MFA is not enabled',
            })
        violations.append({
            'control': 'CIS-AWS-2',
            'resource': 'root-account',
            'severity': 'CRITICAL',
            'message': 'Root access keys check - Manual verification required',
        })
    except Exception as e:
        print(f"Error scanning IAM: {str(e)}")
    return violations


def scan_cloudtrail_controls() -> List[Dict[str, Any]]:
    violations = []
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        if not trails:
            violations.append({
                'control': 'CIS-AWS-3',
                'resource': 'cloudtrail',
                'severity': 'HIGH',
                'message': 'No CloudTrail found',
            })
            return violations

        for trail in trails:
            trail_name = trail['Name']
            trail_arn = trail['TrailARN']
            if not trail.get('IsMultiRegionTrail', False):
                violations.append({
                    'control': 'CIS-AWS-3',
                    'resource': trail_name,
                    'resource_arn': trail_arn,
                    'severity': 'HIGH',
                    'message': f'CloudTrail {trail_name} not enabled in all regions',
                })
            if not trail.get('LogFileValidationEnabled', False):
                violations.append({
                    'control': 'CIS-AWS-4',
                    'resource': trail_name,
                    'resource_arn': trail_arn,
                    'severity': 'HIGH',
                    'message': f'CloudTrail {trail_name} log validation not enabled',
                })
    except Exception as e:
        print(f"Error scanning CloudTrail: {str(e)}")
    return violations


def scan_s3_controls() -> List[Dict[str, Any]]:
    violations = []
    try:
        buckets = s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                public_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_block['PublicAccessBlockConfiguration']
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    violations.append({
                        'control': 'CIS-AWS-5',
                        'resource': bucket_name,
                        'severity': 'CRITICAL',
                        'message': f'S3 bucket {bucket_name} allows public access',
                    })
            except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                violations.append({
                    'control': 'CIS-AWS-5',
                    'resource': bucket_name,
                    'severity': 'CRITICAL',
                    'message': f'S3 bucket {bucket_name} has no public access block',
                })
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
            except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                violations.append({
                    'control': 'CIS-AWS-6',
                    'resource': bucket_name,
                    'severity': 'HIGH',
                    'message': f'S3 bucket {bucket_name} encryption not enabled',
                })
    except Exception as e:
        print(f"Error scanning S3: {str(e)}")
    return violations


def scan_security_group_controls() -> List[Dict[str, Any]]:
    violations = []
    try:
        security_groups = ec2_client.describe_security_groups()['SecurityGroups']
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            is_default = sg_name == 'default'
            if is_default and (sg['IpPermissions'] or sg['IpPermissionsEgress']):
                violations.append({
                    'control': 'CIS-AWS-9',
                    'resource': sg_id,
                    'severity': 'HIGH',
                    'message': f'Default security group {sg_id} has rules',
                })
            for rule in sg['IpPermissions']:
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if from_port == 22 and to_port == 22 and cidr == '0.0.0.0/0':
                        violations.append({
                            'control': 'CIS-AWS-7',
                            'resource': sg_id,
                            'severity': 'CRITICAL',
                            'message': f'Security group {sg_id} allows SSH from internet',
                        })
                    if from_port == 3389 and to_port == 3389 and cidr == '0.0.0.0/0':
                        violations.append({
                            'control': 'CIS-AWS-8',
                            'resource': sg_id,
                            'severity': 'CRITICAL',
                            'message': f'Security group {sg_id} allows RDP from internet',
                        })
    except Exception as e:
        print(f"Error scanning Security Groups: {str(e)}")
    return violations


def scan_vpc_controls() -> List[Dict[str, Any]]:
    violations = []
    try:
        vpcs = ec2_client.describe_vpcs()['Vpcs']
        flow_logs = ec2_client.describe_flow_logs()['FlowLogs']
        vpcs_with_logs = {fl['ResourceId'] for fl in flow_logs if fl['ResourceId'].startswith('vpc-')}
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            if vpc_id not in vpcs_with_logs:
                violations.append({
                    'control': 'CIS-AWS-10',
                    'resource': vpc_id,
                    'severity': 'MEDIUM',
                    'message': f'VPC {vpc_id} flow logs not enabled',
                })
    except Exception as e:
        print(f"Error scanning VPC: {str(e)}")
    return violations


def scan_ec2_instances() -> List[Dict[str, Any]]:
    violations = []
    try:
        reservations = ec2_client.describe_instances()['Reservations']
        for r in reservations:
            for i in r['Instances']:
                instance_id = i['InstanceId']
                state = i['State']['Name']
                if state != 'running':
                    continue
                public_ip = i.get('PublicIpAddress')
                if public_ip:
                    violations.append({
                        'control': 'CIS-AWS-EC2-1',
                        'resource': instance_id,
                        'severity': 'HIGH',
                        'message': f'EC2 instance {instance_id} has public IP {public_ip}',
                    })
    except Exception as e:
        print(f"Error scanning EC2 instances: {str(e)}")
    return violations


# ---- Helper functions ----

def save_scan_results(violations: List[Dict[str, Any]]):
    try:
        timestamp = datetime.now().isoformat()
        filename = f"scans/{timestamp}.json"

        s3_client.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=filename,
            Body=json.dumps({
                'timestamp': timestamp,
                'environment': ENVIRONMENT,
                'total_violations': len(violations),
                'violations': violations
            }, indent=2),
            ContentType='application/json'
        )

        s3_client.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key='latest.json',
            Body=json.dumps({
                'timestamp': timestamp,
                'environment': ENVIRONMENT,
                'total_violations': len(violations),
                'violations': violations
            }, indent=2),
            ContentType='application/json'
        )

        print(f"Scan results saved to s3://{EVIDENCE_BUCKET}/{filename}")

    except Exception as e:
        print(f"Error saving scan results: {str(e)}")


def publish_metrics(violations: List[Dict[str, Any]]):
    try:
        cloudwatch_client.put_metric_data(
            Namespace='Compliance',
            MetricData=[
                {
                    'MetricName': 'ViolationCount',
                    'Value': len(violations),
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Environment', 'Value': ENVIRONMENT}]
                },
                {
                    'MetricName': 'CriticalViolations',
                    'Value': len([v for v in violations if v['severity'] == 'CRITICAL']),
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Environment', 'Value': ENVIRONMENT}]
                }
            ]
        )
        print("Metrics published to CloudWatch")
    except Exception as e:
        print(f"Error publishing metrics: {str(e)}")

