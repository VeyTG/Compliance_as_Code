control 's3-1.1' do
  impact 1.0
  title 'S3 buckets không được public'
  describe aws_s3_bucket(bucket_name: 'my-compliance-test-bucket-123') do
    it { should_not be_public }
  end
end

control 's3-1.2' do
  impact 1.0
  title 'S3 buckets phải mã hóa'
  describe aws_s3_bucket(bucket_name: 'my-compliance-test-bucket-123') do
    it { should have_default_encryption_enabled }
  end
end

control 'cloudtrail-1.1' do
  impact 1.0
  title 'CloudTrail phải bật'
  describe aws_cloudtrail_trail('example-trail') do
    it { should be_enabled }
  end
end
