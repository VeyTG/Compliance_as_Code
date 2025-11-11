Dự án **AWS Compliance Demo** minh họa cách tự động quét các tài nguyên AWS theo **CIS Benchmark**, phát hiện vi phạm (violations), lưu kết quả, và hiển thị trên dashboard. Lambda functions được dùng để scan và remediate tự động các vi phạm.

---

## 🔹 Mục tiêu dự án

- Tự động quét các AWS resources: **EC2, S3, IAM, CloudTrail, Security Groups, VPC**.
- Phát hiện các vi phạm bảo mật theo CIS AWS Benchmark.
- Lưu kết quả vào **S3 bucket**.
- Publish metrics lên **CloudWatch**.
- Tự động remediate các vi phạm có thể fix được.
- Dashboard trực quan hiển thị tổng quan violations.

---

## 📂 Cấu trúc dự án

aws-compliance-demo/
│
├── scanner.py # Lambda function thực hiện scan
├── remediation.py # Lambda function xử lý remediation
├── app.py # Dashboard hiển thị violations
├── demo_checklist.md # Hướng dẫn demo từng bước
├── terraform/ # Terraform IaC deploy AWS resources
├── requirements.txt # Dependencies Python
└── README.md # File hướng dẫn dự án

---

## ⚡ Chuẩn bị môi trường

1. AWS account với quyền **Administrator** hoặc đủ quyền Lambda, S3, IAM, CloudWatch.
2. Cài đặt **AWS CLI** và **Python 3.10+**.
3. Terraform (nếu muốn deploy hạ tầng tự động).
4. Thiết lập biến môi trường trong Lambda:

```text
EVIDENCE_BUCKET=<tên bucket lưu scan kết quả>
REMEDIATION_FUNCTION=<tên Lambda remediation>
SNS_TOPIC_ARN=<ARN topic SNS nếu muốn notification>
ENVIRONMENT=dev
```

---


## 🚀 Hướng dẫn chạy demo

1️⃣ Tạo resource vi phạm
Tạo một EC2 public IP và S3 public bucket để Lambda scanner phát hiện:
  aws ec2 run-instances ... --associate-public-ip-address
  aws s3 mb s3://demo-public-bucket-12345
  aws s3api put-public-access-block --bucket demo-public-bucket-12345 --public-access-block-configuration ...

2️⃣ Chạy Lambda scanner
Invoke Lambda function để scan toàn bộ account:
  aws lambda invoke \
      --function-name scanner \
      --payload '{}' \
      response.json \
      --region us-east-1
  
  cat response.json | jq .

3️⃣ Xem log CloudWatch
Kiểm tra chi tiết log để debug hoặc xem violations:
  aws logs filter-log-events --log-group-name /aws/lambda/scanner --limit 20

4️⃣ Kiểm tra kết quả S3
Download và xem file scan results:
  aws s3 ls $EVIDENCE_BUCKET
  aws s3 cp s3://$EVIDENCE_BUCKET/latest.json .
  cat latest.json | jq .

5️⃣ Chạy Dashboard
  python3 app.py

---

## 📊 Metrics & Remediation

Metrics violations được publish lên CloudWatch.
Lambda remediation tự động fix các vi phạm có thể fix được.
Các vi phạm không fix được sẽ hiển thị trên dashboard để thao tác thủ công.

---

## 🛠️ Công nghệ sử dụng

AWS Services: Lambda, S3, EC2, IAM, CloudTrail, CloudWatch, SNS
IaC: Terraform
Python: boto3, Flask (dashboard)
Visualization: Dashboard trực quan violations
