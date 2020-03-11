module "detect_unencrypted_ebs_volume" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.5.1"
  rule_name        = "DetectUnencryptedEBSVolume"
  rule_description = "Rule to check when EBS volumes are created without encryption."

  event_pattern = <<PATTERN
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "source": [
    "aws.ec2"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "CreateVolume"
    ],
    "responseElements": {
      "encrypted": [false]
    }
  }
}
PATTERN

  function_name   = "DetectUnencryptedEBSVolume"
  source_code_dir = "${path.module}/source"
  handler         = "unencrypted_ebs_volume.lambda_handler"
  lambda_runtime  = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn
  }
  custom_lambda_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetEncryptionConfiguration"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

  queue_name    = "DetectUnencryptedEBSVolume"
  delay_seconds = 60

  target_id  = "DetectUnencryptedEBSVolume"

  sns_topic_arn = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
