""" Module for detecting unencrypted EBS volumes """

import json

from reflex_core import AWSRule, subscription_confirmation


class EbsVolumeNotEncrypted(AWSRule):
    """ AWS rule for detecting unencrypted EBS volumes """

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required data from the event """
        self.volume_id = event["detail"]["responseElements"]["volumeId"]

    def resource_compliant(self):
        """ Determines if the resource is compliant. Returns True if compliant, False otherwise """
        # We simply want to know when this event occurs. Since this rule was
        # triggered we know that happened, and we want to alert. Therefore
        # the resource is never compliant.
        return False

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"An unencrypted EBS volume was created. VolumeId: {self.volume_id}."


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = EbsVolumeNotEncrypted(event_payload)
    rule.run_compliance_rule()
