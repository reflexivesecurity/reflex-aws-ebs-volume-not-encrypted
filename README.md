# reflex-aws-detect-unencrypted-ebs-volume
A Reflex rule for detecting unencrypted EBS volumes.

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
version: 0.1

providers:
  - aws

measures:
  - reflex-aws-detect-unencrypted-ebs-volume
```

or add it directly to your Terraform:  
```
...

module "reflex-aws-detect-unencrypted-ebs-volume" {
  source           = "github.com/cloudmitigator/reflex-aws-detect-unencrypted-ebs-volume"
  email            = "example@example.com"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-detect-unencrypted-ebs-volume/blob/master/LICENSE) 
