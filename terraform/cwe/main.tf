module "cwe" {
  source      = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/cwe?ref=v2.1.3"
  name        = "EbsVolumeNotEncrypted"
  description = "Rule to check when EBS volumes are created without encryption."

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

}
