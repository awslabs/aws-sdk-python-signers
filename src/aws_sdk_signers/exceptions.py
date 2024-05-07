class AWSSDKWarning(UserWarning): ...


class BaseAWSSDKException(Exception):
    """Top-level exception to capture SDK-related errors."""

    ...


class MissingExpectedParameterException(BaseAWSSDKException, ValueError):
    """Some APIs require specific signing properties to be present."""

    ...
