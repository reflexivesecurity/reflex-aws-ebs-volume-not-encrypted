provider "aws" {
  region = "us-east-1"
}

module "detect_unencrypted_ebs_volume" {
  source           = "git@github.com:cloudmitigator/reflex.git//modules/cwe_sns_email?ref=v0.2.0"
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

  topic_name = "DetectUnencryptedEBSVolume"
  target_id  = "DetectUnencryptedEBSVolume"
  sns_topic_arn = var.sns_topic_arn
}
