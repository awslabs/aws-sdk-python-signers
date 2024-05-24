## AWS SDK Python Signers

AWS SDK Python Signers provides stand-alone signing functionality. This enables users to
create standardized request signatures (currently only SigV4) and apply them to
common HTTP utilities like AIOHTTP, Curl, Postman, Requests and urllib3.

This project is currently in an **Alpha** phase of development. There likely
will be breakages and redesigns between minor patch versions as we collect
user feedback. We strongly recommend pinning to a minor version and reviewing
the changelog carefully before upgrading.

As you find issues, please feel free to open an issue on this GitHub repository
and we're happy to discuss direction and design decisions, along with potential
bug fixes.

## Getting Started

Currently, the `aws-sdk-signers` module provides two high level signers,
`AsyncSigV4Signer` and `SigV4Signer`.

Both of these signers takes three inputs to their primary `sign` method.

* A [**SigV4SigningProperties**](https://github.com/awslabs/aws-sdk-python-signers/blob/eb78cde3b65a82ae052d632b43ba960a83643f8f/src/aws_sdk_signers/signers.py#L38-L42) object defining:
     The service for the request,
     The intended AWS region (e.g. us-west-2),
     An optional date that will be auto-populated with the current time if not supplied,
     An optional boolean, payload_signing_enabled to toggle payload signing. True by default.
* An [**AWSRequest**](https://github.com/awslabs/aws-sdk-python-signers/blob/eb78cde3b65a82ae052d632b43ba960a83643f8f/src/aws_sdk_signers/_http.py#L336), similar to the AWSRequest object from boto3 or Requests.
* An [**AWSCredentialIdentity**](https://github.com/awslabs/aws-sdk-python-signers/blob/eb78cde3b65a82ae052d632b43ba960a83643f8f/src/aws_sdk_signers/_identity.py#L12-L24), an dataclass holding standard AWS credential information.

The signers can be used independently to build signing integrations with your favorite
HTTP client or with the example code provided in the [`/examples`](https://github.com/awslabs/aws-sdk-python-signers/blob/main/examples/) directory. Currently,
we have high-level code for integration with AIOHTTP, Curl, and Requests. More integrations
may be introduced as we receive interest. You can find sample code for getting started
with our current offerings in the [examples/README.md](https://github.com/awslabs/aws-sdk-python-signers/blob/main/examples/README.md).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
