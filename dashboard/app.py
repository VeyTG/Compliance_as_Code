"""
Flask Dashboard cho AWS Compliance Monitoring
Hiển thị compliance score và violations
"""

from flask import Flask, render_template, jsonify
import boto3
import json
import os
from datetime import datetime

app = Flask(__name__)

# AWS client
s3_client = boto3.client('s3')

# Config
EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET', 'compliance-evidence-bucket')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')


@app.route('/')
def index():
    """
    Dashboard chính - hiển thị compliance score và violations
    """
    try:
        # Load latest scan results
        scan_data = load_latest_scan()

        if not scan_data:
            return render_template('dashboard.html',
                                   error="No scan data available",
                                   score=0,
                                   violations=[])

        violations = scan_data.get('violations', [])
        timestamp = scan_data.get('timestamp', 'N/A')

        # Calculate metrics
        total_checks = 10
        total_violations = len(violations)
        score = calculate_score(total_checks, total_violations)

        # Group by severity
        critical = [v for v in violations if v['severity'] == 'CRITICAL']
        high = [v for v in violations if v['severity'] == 'HIGH']
        medium = [v for v in violations if v['severity'] == 'MEDIUM']

        # Group by control
        controls = {}
        for v in violations:
            control = v.get('control', 'Unknown')
            if control not in controls:
                controls[control] = []
            controls[control].append(v)

        return render_template('dashboard.html',
                               score=score,
                               total_checks=total_checks,
                               total_violations=total_violations,
                               critical_count=len(critical),
                               high_count=len(high),
                               medium_count=len(medium),
                               violations=violations,
                               controls=controls,
                               timestamp=timestamp)

    except Exception as e:
        app.logger.error(f"Error loading dashboard: {str(e)}")
        return render_template('dashboard.html',
                               error=str(e),
                               score=0,
                               violations=[])


@app.route('/api/status')
def api_status():
    """
    API endpoint - return compliance status as JSON
    """
    try:
        scan_data = load_latest_scan()

        if not scan_data:
            return jsonify({'error': 'No scan data available'}), 404

        violations = scan_data.get('violations', [])
        total_checks = 10
        total_violations = len(violations)
        score = calculate_score(total_checks, total_violations)

        return jsonify({
            'score': score,
            'total_checks': total_checks,
            'total_violations': total_violations,
            'critical': len([v for v in violations if v['severity'] == 'CRITICAL']),
            'high': len([v for v in violations if v['severity'] == 'HIGH']),
            'medium': len([v for v in violations if v['severity'] == 'MEDIUM']),
            'timestamp': scan_data.get('timestamp'),
            'violations': violations
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/violations/<control_id>')
def api_violations_by_control(control_id):
    """
    API endpoint - get violations by control ID
    """
    try:
        scan_data = load_latest_scan()

        if not scan_data:
            return jsonify({'error': 'No scan data available'}), 404

        violations = scan_data.get('violations', [])
        control_violations = [v for v in violations if v.get('control') == control_id]

        return jsonify({
            'control': control_id,
            'count': len(control_violations),
            'violations': control_violations
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan_history')
def api_scan_history():
    """
    API endpoint - get scan history
    """
    try:
        # List all scans from S3
        response = s3_client.list_objects_v2(
            Bucket=EVIDENCE_BUCKET,
            Prefix='scans/',
            MaxKeys=10
        )

        scans = []
        for obj in response.get('Contents', []):
            key = obj['Key']
            if key.endswith('.json'):
                try:
                    data = load_scan_from_s3(key)
                    scans.append({
                        'timestamp': data.get('timestamp'),
                        'total_violations': data.get('total_violations'),
                        'key': key
                    })
                except:
                    pass

        # Sort by timestamp (newest first)
        scans.sort(key=lambda x: x['timestamp'], reverse=True)

        return jsonify({
            'count': len(scans),
            'scans': scans
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def load_latest_scan():
    """
    Load latest scan results từ S3
    """
    try:
        response = s3_client.get_object(
            Bucket=EVIDENCE_BUCKET,
            Key='latest.json'
        )
        data = json.loads(response['Body'].read().decode('utf-8'))
        return data

    except s3_client.exceptions.NoSuchKey:
        app.logger.warning("No latest.json found in S3")
        return None
    except Exception as e:
        app.logger.error(f"Error loading latest scan: {str(e)}")
        raise


def load_scan_from_s3(key):
    """
    Load một scan cụ thể từ S3
    """
    response = s3_client.get_object(
        Bucket=EVIDENCE_BUCKET,
        Key=key
    )
    return json.loads(response['Body'].read().decode('utf-8'))


def calculate_score(total_checks, violations):
    """
    Tính compliance score (0-100)
    """
    if total_checks == 0:
        return 0

    passed = total_checks - violations
    if passed < 0:
        passed = 0

    score = int((passed / total_checks) * 100)
    return score


if __name__ == '__main__':
    # Get config from environment
    host = os.environ.get('DASHBOARD_HOST', '0.0.0.0')
    port = int(os.environ.get('DASHBOARD_PORT', 5050))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'

    print(f"Starting Compliance Dashboard on {host}:{port}")
    print(f"Evidence bucket: {EVIDENCE_BUCKET}")
    print(f"AWS Region: {AWS_REGION}")

    app.run(host=host, port=port, debug=debug)
