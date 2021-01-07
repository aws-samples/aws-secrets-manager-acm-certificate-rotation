## AWS Secrets Manager ACM Certificate Rotation

This repository contains a Lambda function used to maintain the lifecylce of AWS Certificate Manager private certificates using AWS Secrets Manager. It also includes CloudFormation templates that launch a sample environment used to test this lifecycle management. 

Please see a walk-through of using this function in [Storing and Renewing Private Certificates using Secrets Manager](https://aws.amazon.com/blogs/security/use-aws-secrets-manager-to-simplify-the-management-of-private-certificates/).

## Setup
To set up the resources in this repository, complete the following:
1. Upload the crypto_layer.zip and rotate_function.zip to an S3 Bucket
2. Follow the directions outlined in the Blog above and reference the uploaded files when launching the src_account.yaml CloudFormation Template

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.
