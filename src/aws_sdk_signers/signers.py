from collections.abc import AsyncIterable, Iterable
from copy import deepcopy
from dataclasses import dataclass
import datetime
from hashlib import sha256
import hmac
from typing import Required, TypedDict
from urllib.parse import parse_qsl, quote

from ._http import URI, AWSRequest, Fields, Field
from ._identity import AWSCredentialIdentity

HEADERS_EXCLUDED_FROM_SIGNING: tuple[str, ...] = (
    "authorization",
    "expect",
    "user-agent",
    "x-amz-content-sha256",
    "x-amzn-trace-id",
)
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

SIGV4_TIMESTAMP_FORMAT: str = "%Y%m%dT%H%M%SZ"
UNSIGNED_PAYLOAD: str = "UNSIGNED-PAYLOAD"
EMPTY_SHA256_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class Configuration:
    # TODO: Add Config Options
    ...


@dataclass
class SigningComponents:
    uri: URI
    fields: Fields
    body: Iterable[bytes]


class SigV4SigningProperties(TypedDict, total=False):
    region: Required[str]
    service: Required[str]
    date: str
    expires: int
    payload_signing_enabled: bool


class SigV4Signer:
    """
    Request signer for applying the AWS Signature Version 4 algorithm.
    """

    def __init__(self, *, config: Configuration | None = None):
        self._config = config

    def sign(
        self,
        *,
        signing_properties: SigV4SigningProperties,
        request: AWSRequest,
        identity: AWSCredentialIdentity,
    ) -> AWSRequest:
        # Copy and prepopulate any missing values in the
        # supplied request and signing properties.
        self._validate_identity(identity=identity)
        new_signing_properties = self._normalize_signing_properties(
            signing_properties=signing_properties
        )
        new_request = self._generate_new_request(request=request)

        # Construct core signing components
        canonical_request = self.canonical_request(
            signing_properties=signing_properties,
            request=request,
        )
        string_to_sign = self.string_to_sign(
            canonical_request=canonical_request,
            signing_properties=new_signing_properties,
        )
        signature = self._signature(
            string_to_sign=string_to_sign,
            secret_key=identity.secret_access_key,
            signing_properties=new_signing_properties,
        )

        signing_fields = self._normalize_signing_fields(request=request)
        credential_scope = self._scope(signing_properties=new_signing_properties)
        credential = f"{identity.access_key_id}/{credential_scope}"
        authorization = self.generate_authorization_field(
            credential=credential,
            signed_headers=list(signing_fields.keys()),
            signature=signature,
        )
        new_request.fields.set_field(authorization)

        return new_request

    def generate_authorization_field(
        self, *, credential: str, signed_headers: list[str], signature: str
    ) -> Field:
        """Generate the `Authorization` field"""
        signed_headers_str = ";".join(signed_headers)
        auth_str = (
            f"AWS4-HMAC-SHA256 Credential={credential}, "
            f"SignedHeaders={signed_headers_str}, Signature={signature}"
        )
        return Field(name="Authorization", values=[auth_str])

    def _signature(
        self,
        *,
        string_to_sign: str,
        secret_key: str,
        signing_properties: SigV4SigningProperties,
    ) -> str:
        """Sign the string to sign.

        In SigV4, a signing key is created that is scoped to a specific region and
        service. The date, region, service and resulting signing key are individually
        hashed, then the composite hash is used to sign the string to sign.

        DateKey              = HMAC-SHA256("AWS4"+"<SecretAccessKey>", "<YYYYMMDD>")
        DateRegionKey        = HMAC-SHA256(<DateKey>, "<aws-region>")
        DateRegionServiceKey = HMAC-SHA256(<DateRegionKey>, "<aws-service>")
        SigningKey           = HMAC-SHA256(<DateRegionServiceKey>, "aws4_request")
        """
        assert signing_properties["date"] is not None
        k_date = self._hash(
            key=f"AWS4{secret_key}".encode(), value=signing_properties["date"][0:8]
        )
        k_region = self._hash(key=k_date, value=signing_properties["region"])
        k_service = self._hash(key=k_region, value=signing_properties["service"])
        k_signing = self._hash(key=k_service, value="aws4_request")

        return self._hash(key=k_signing, value=string_to_sign).hex()

    def _hash(self, key: bytes, value: str) -> bytes:
        return hmac.new(key=key, msg=value.encode(), digestmod=sha256).digest()

    def _validate_identity(self, *, identity: AWSCredentialIdentity) -> None:
        """Perform runtime and expiration checks before attempting signing."""
        if not isinstance(identity, AWSCredentialIdentity):
            raise ValueError(
                "Received unexpected value for identity parameter. Expected "
                f"AWSCredentialIdentity but received {type(identity)}."
            )
        elif identity.is_expired:
            raise ValueError(
                f"Provided identity expired at {identity.expiration}. Please "
                "refresh the credentials or update the expiration parameter."
            )

    def _normalize_signing_properties(
        self, *, signing_properties: SigV4SigningProperties
    ) -> SigV4SigningProperties:
        # Create copy of signing properties to avoid mutating the original
        new_signing_properties = SigV4SigningProperties(**signing_properties)
        new_signing_properties["date"] = self._resolve_signing_date(
            date=new_signing_properties.get("date")
        )
        return new_signing_properties

    def _generate_new_request(self, *, request: AWSRequest) -> AWSRequest:
        return deepcopy(request)

    def _resolve_signing_date(self, *, date: str | None) -> str:
        if date is None:
            date_obj = datetime.datetime.now(datetime.timezone.utc)
            date = date_obj.strftime(SIGV4_TIMESTAMP_FORMAT)
        return date

    def canonical_request(
        self, *, signing_properties: SigV4SigningProperties, request: AWSRequest
    ) -> str:
        canonical_path = self._format_canonical_path(path=request.destination.path)
        canonical_query = self._format_canonical_query(query=request.destination.query)
        normalized_fields = self._normalize_signing_fields(request=request)
        canonical_fields = self._format_canonical_fields(fields=normalized_fields)
        canonical_payload = self._format_canonical_payload(
            body=request.body, signing_properties=signing_properties
        )
        return (
            f"{request.method.upper()}\n"
            f"{canonical_path}\n"
            f"{canonical_query}\n"
            f"{canonical_fields}\n"
            f"{';'.join(normalized_fields)}\n"
            f"{canonical_payload}"
        )

    def string_to_sign(
        self,
        *,
        canonical_request: str,
        signing_properties: SigV4SigningProperties,
    ) -> str:
        date = signing_properties.get("date")
        if date is None:
            # TODO: figure out error type here
            raise ValueError(
                "Cannot generate string_to_sign without a valid date "
                f"in your signing_properties. Current value: {date}"
            )
        return (
            "AWS4-HMAC-SHA256\n"
            f"{date}\n"
            f"{self._scope(signing_properties=signing_properties)}\n"
            f"{sha256(canonical_request.encode()).hexdigest()}"
        )

    def _scope(self, signing_properties: SigV4SigningProperties) -> str:
        formatted_date = signing_properties["date"][0:8]
        region = signing_properties["region"]
        service = signing_properties["service"]
        # Scope format: <YYYYMMDD>/<AWS Region>/<AWS Service>/aws4_request
        return f"{formatted_date}/{region}/{service}/aws4_request"

    def _format_canonical_path(self, *, path: str | None) -> str:
        if path is None:
            path = "/"
        normalized_path = _remove_dot_segments(path)
        return quote(string=normalized_path, safe="/%")

    def _format_canonical_query(self, *, query: str | None) -> str:
        if query is None:
            return ""

        query_params = parse_qsl(qs=query)
        query_parts = (
            (quote(string=key, safe=""), quote(string=value, safe=""))
            for key, value in query_params
        )
        # key-value pairs must be in sorted order for their encoded forms.
        return "&".join(f"{key}={value}" for key, value in sorted(query_parts))

    def _normalize_signing_fields(self, *, request: AWSRequest) -> dict[str, str]:
        normalized_fields = {
            field.name.lower(): field.as_string(delimiter=",")
            for field in request.fields
            if field.name.lower() not in HEADERS_EXCLUDED_FROM_SIGNING
        }
        if "host" not in normalized_fields:
            normalized_fields["host"] = self._normalize_host_field(
                uri=request.destination
            )

        return dict(sorted(normalized_fields.items()))

    def _normalize_host_field(self, *, uri: URI) -> str:
        if uri.port is not None and DEFAULT_PORTS.get(uri.scheme) == uri.port:
            # TODO: Fix typing mess here. Unpack doesn't do what we want.
            pass
            """
            uri_dict = uri.to_dict()
            uri_dict.update({"port": None})
            uri = URI(**uri_dict)
            """
        return uri.netloc

    def _format_canonical_fields(self, *, fields: dict[str, str]) -> str:
        return "".join(
            f"{key}:{' '.join(value.split())}\n" for key, value in fields.items()
        )

    def _format_canonical_payload(
        self,
        *,
        body: AsyncIterable[bytes] | Iterable[bytes],
        signing_properties: SigV4SigningProperties,
    ) -> str:
        if isinstance(body, AsyncIterable):
            raise TypeError(
                "An async body was attached to a synchronous signer. Please use "
                "AsyncSigV4Signer for async AWSRequests or ensure your body is "
                "of type Iterable[bytes]."
            )
        # TODO: Add ability to sign body
        return EMPTY_SHA256_HASH


class AsyncSigV4Signer:
    def __init__(self, *, config: Configuration):
        self._config = config

    async def sign(
        self,
        *,
        signing_properties: SigV4SigningProperties,
        request: AWSRequest,
        identity: AWSCredentialIdentity,
    ) -> AWSRequest:
        # Copy and prepopulate any missing values in the
        # supplied request and signing properties.

        await self._validate_identity(identity=identity)
        new_signing_properties = await self._normalize_signing_properties(
            signing_properties=signing_properties
        )
        new_request = await self._generate_new_request(request=request)

        # Construct core signing components
        canonical_request = await self.canonical_request(
            signing_properties=signing_properties,
            request=request,
        )
        string_to_sign = await self.string_to_sign(
            canonical_request=canonical_request,
            signing_properties=new_signing_properties,
        )
        signature = await self._signature(
            string_to_sign=string_to_sign,
            secret_key=identity.secret_access_key,
            signing_properties=new_signing_properties,
        )

        signing_fields = await self._normalize_signing_fields(request=request)
        credential_scope = await self._scope(signing_properties=new_signing_properties)
        credential = f"{identity.access_key_id}/{credential_scope}"
        authorization = await self.generate_authorization_field(
            credential=credential,
            signed_headers=list(signing_fields.keys()),
            signature=signature,
        )
        new_request.fields.set_field(authorization)
        return new_request

    async def generate_authorization_field(
        self, *, credential: str, signed_headers: list[str], signature: str
    ) -> Field:
        """Generate the `Authorization` field"""
        signed_headers_str = ";".join(signed_headers)
        auth_str = (
            f"AWS4-HMAC-SHA256 Credential={credential}, "
            f"SignedHeaders={signed_headers_str}, Signature={signature}"
        )
        return Field(name="Authorization", values=[auth_str])

    async def _signature(
        self,
        *,
        string_to_sign: str,
        secret_key: str,
        signing_properties: SigV4SigningProperties,
    ) -> str:
        """Sign the string to sign.

        In SigV4, a signing key is created that is scoped to a specific region and
        service. The date, region, service and resulting signing key are individually
        hashed, then the composite hash is used to sign the string to sign.

        DateKey              = HMAC-SHA256("AWS4"+"<SecretAccessKey>", "<YYYYMMDD>")
        DateRegionKey        = HMAC-SHA256(<DateKey>, "<aws-region>")
        DateRegionServiceKey = HMAC-SHA256(<DateRegionKey>, "<aws-service>")
        SigningKey           = HMAC-SHA256(<DateRegionServiceKey>, "aws4_request")
        """
        assert signing_properties.get("date") is not None
        k_date = await self._hash(
            key=f"AWS4{secret_key}".encode(), value=signing_properties["date"][0:8]
        )
        k_region = await self._hash(key=k_date, value=signing_properties["region"])
        k_service = await self._hash(key=k_region, value=signing_properties["service"])
        k_signing = await self._hash(key=k_service, value="aws4_request")
        final_hash = await self._hash(key=k_signing, value=string_to_sign)

        return final_hash.hex()

    async def _hash(self, key: bytes, value: str) -> bytes:
        return hmac.new(key=key, msg=value.encode(), digestmod=sha256).digest()

    async def _validate_identity(self, *, identity: AWSCredentialIdentity) -> None:
        """Perform runtime and expiration checks before attempting signing."""
        if not isinstance(identity, AWSCredentialIdentity):
            raise ValueError(
                "Received unexpected value for identity parameter. Expected "
                f"AWSCredentialIdentity but received {type(identity)}."
            )
        elif identity.is_expired:
            raise ValueError(
                f"Provided identity expired at {identity.expiration}. Please "
                "refresh the credentials or update the expiration parameter."
            )

    async def _normalize_signing_properties(
        self, *, signing_properties: SigV4SigningProperties
    ) -> SigV4SigningProperties:
        # Create copy of signing properties to avoid mutating the original
        new_signing_properties = SigV4SigningProperties(**signing_properties)
        new_signing_properties["date"] = await self._resolve_signing_date(
            date=new_signing_properties.get("date")
        )
        return new_signing_properties

    async def _generate_new_request(self, *, request: AWSRequest) -> AWSRequest:
        return deepcopy(request)

    async def _resolve_signing_date(self, *, date: str | None) -> str:
        if date is None:
            date_obj = datetime.datetime.now(datetime.timezone.utc)
            date = date_obj.strftime(SIGV4_TIMESTAMP_FORMAT)
        return date

    async def canonical_request(
        self, *, signing_properties: SigV4SigningProperties, request: AWSRequest
    ) -> str:
        canonical_path = await self._format_canonical_path(
            path=request.destination.path
        )
        canonical_query = await self._format_canonical_query(
            query=request.destination.query
        )
        normalized_fields = await self._normalize_signing_fields(request=request)
        canonical_fields = await self._format_canonical_fields(fields=normalized_fields)
        canonical_payload = await self._format_canonical_payload(
            body=request.body, signing_properties=signing_properties
        )
        return (
            f"{request.method.upper()}\n"
            f"{canonical_path}\n"
            f"{canonical_query}\n"
            f"{canonical_fields}\n"
            f"{';'.join(normalized_fields)}\n"
            f"{canonical_payload}"
        )

    async def string_to_sign(
        self,
        *,
        canonical_request: str,
        signing_properties: SigV4SigningProperties,
    ) -> str:
        date = signing_properties.get("date")
        if date is None:
            # TODO: figure out error type here
            raise ValueError(
                "Cannot generate string_to_sign without a valid date "
                f"in your signing_properties. Current value: {date}"
            )
        return (
            "AWS4-HMAC-SHA256\n"
            f"{date}\n"
            f"{self._scope(signing_properties=signing_properties)}\n"
            f"{sha256(canonical_request.encode()).hexdigest()}"
        )

    async def _scope(self, signing_properties: SigV4SigningProperties) -> str:
        formatted_date = signing_properties["date"][0:8]
        region = signing_properties["region"]
        service = signing_properties["service"]
        # Scope format: <YYYYMMDD>/<AWS Region>/<AWS Service>/aws4_request
        return f"{formatted_date}/{region}/{service}/aws4_request"

    async def _format_canonical_path(self, *, path: str | None) -> str:
        if path is None:
            path = "/"
        normalized_path = _remove_dot_segments(path)
        return quote(string=normalized_path, safe="/%")

    async def _format_canonical_query(self, *, query: str | None) -> str:
        if query is None:
            return ""

        query_params = parse_qsl(qs=query)
        query_parts = (
            (quote(string=key, safe=""), quote(string=value, safe=""))
            for key, value in query_params
        )
        # key-value pairs must be in sorted order for their encoded forms.
        return "&".join(f"{key}={value}" for key, value in sorted(query_parts))

    async def _normalize_signing_fields(self, *, request: AWSRequest) -> dict[str, str]:
        normalized_fields = {
            field.name.lower(): field.as_string(delimiter=",")
            for field in request.fields
            if field.name.lower() not in HEADERS_EXCLUDED_FROM_SIGNING
        }
        if "host" not in normalized_fields:
            normalized_fields["host"] = await self._normalize_host_field(
                uri=request.destination
            )

        return dict(sorted(normalized_fields.items()))

    async def _normalize_host_field(self, *, uri: URI) -> str:
        if uri.port is not None and DEFAULT_PORTS.get(uri.scheme) == uri.port:
            # TODO: Fix typing mess here. Unpack doesn't do what we want.
            pass
            """
            uri_dict = uri.to_dict()
            uri_dict.update({"port": None})
            uri = URI(**uri_dict)
            """
        return uri.netloc

    async def _format_canonical_fields(self, *, fields: dict[str, str]) -> str:
        return "".join(
            f"{key}:{' '.join(value.split())}\n" for key, value in fields.items()
        )

    async def _format_canonical_payload(
        self,
        *,
        body: AsyncIterable[bytes] | Iterable[bytes],
        signing_properties: SigV4SigningProperties,
    ) -> str:
        if not isinstance(body, AsyncIterable):
            # TODO: Warn on sync body.
            pass
        # TODO: Add ability to sign body
        return EMPTY_SHA256_HASH


def _remove_dot_segments(path: str, remove_consecutive_slashes: bool = True) -> str:
    """Removes dot segments from a path per :rfc:`3986#section-5.2.4`.
    Optionally removes consecutive slashes, true by default.
    :param path: The path to modify.
    :param remove_consecutive_slashes: Whether to remove consecutive slashes.
    :returns: The path with dot segments removed.
    """
    output = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        elif segment != "..":
            output.append(segment)
        elif output:
            output.pop()
    if path.startswith("/") and (not output or output[0]):
        output.insert(0, "")
    if output and path.endswith(("/.", "/..")):
        output.append("")
    result = "/".join(output)
    if remove_consecutive_slashes:
        result = result.replace("//", "/")
    return result
