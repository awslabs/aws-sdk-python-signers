"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
"""

import re
from io import BytesIO

import pytest

from aws_sdk_signers.signers import SigV4Signer, SigV4SigningProperties
from aws_sdk_signers import AWSCredentialIdentity, AWSRequest, Fields, URI

SIGV4_RE = re.compile(
    r"AWS4-HMAC-SHA256 "
    r"Credential=(?P<access_key>\w+)/\d+/"
    r"(?P<signing_region>[a-z0-9-]+)/"
)


@pytest.fixture(scope="module")
def aws_identity() -> AWSCredentialIdentity:
    return AWSCredentialIdentity(
        access_key_id="AKID123456",
        secret_access_key="EXAMPLE1234SECRET",
        session_token="X123456SESSION",
    )


class TestSigV4Signer:
    SIGV4_SYNC_SIGNER = SigV4Signer()

    def test_sign(self, aws_identity: AWSCredentialIdentity):
        signing_properties = SigV4SigningProperties(
            region="us-west-2",
            service="ec2",
        )
        request = AWSRequest(
            destination=URI(
                scheme="http",
                host="127.0.0.1",
                port=8000,
            ),
            method="GET",
            body=BytesIO(b"123456"),
            fields=Fields({}),
        )

        signed_request = self.SIGV4_SYNC_SIGNER.sign(
            signing_properties=signing_properties,
            request=request,
            identity=aws_identity,
        )
        assert isinstance(signed_request, AWSRequest)
        assert signed_request is not request
        assert "authorization" in signed_request.fields
        authorization_field = signed_request.fields["authorization"]
        assert SIGV4_RE.match(authorization_field.as_string())
