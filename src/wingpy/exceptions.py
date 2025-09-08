class UnsupportedMethodError(Exception):
    """
    Raised when an unsupported HTTP method is used.

    Some APIs do not support all HTTP methods. All methods must be implemented in client classes. This exception must be raised when an unsupported method is used.
    For example, if a client class does not implement the `put` method, this exception must be raised when the `.put()` method is called.
    """

    pass


class AuthenticationFailure(Exception):
    """
    Raised when API authentication fails.
    """

    pass


class InvalidEndpointError(Exception):
    """
    Raised when the specified API endpoint path is not valid for use in a URL.
    """

    pass


class UnexpectedPayloadError(Exception):
    """
    Raised when the API returned payload with unexpected data structure.
    """

    pass
