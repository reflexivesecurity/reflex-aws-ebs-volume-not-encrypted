provider "aws" {
  region = "us-east-1"
}

module "detect_unencrypted_ebs_volume" {
  source           = "git@github.com:cloudmitigator/reflex.git//modules/cwe_sns_email"
  rule_name        = "DetectUnencryptedEBSVolume"
  rule_description = "Rule to check when MFA Devices are Deactivated"

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
    ]
    "responseElements": {
      "encrypted": false
    }
  }
}
PATTERN

  topic_name = "DetectUnencryptedEBSVolume"
  target_id  = "DetectUnencryptedEBSVolume"
  email      = var.email
}
