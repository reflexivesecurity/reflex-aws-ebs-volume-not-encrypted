module "ebs_volume_not_encrypted" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.6.0"
  rule_name        = "EbsVolumeNotEncrypted"
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

  function_name   = "EbsVolumeNotEncrypted"
  source_code_dir = "${path.module}/source"
  handler         = "ebs_volume_not_encrypted.lambda_handler"
  lambda_runtime  = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn
  }

  queue_name    = "EbsVolumeNotEncrypted"
  delay_seconds = 0

  target_id  = "EbsVolumeNotEncrypted"

  sns_topic_arn = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
