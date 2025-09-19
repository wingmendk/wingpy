# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import json
import re
import threading
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from ssl import SSLContext
from typing import ClassVar, get_type_hints
from urllib.parse import urlparse

import arrow
import httpx
from lxml import etree

from wingpy.exceptions import (
    AuthenticationFailure,
    MissingPathParameterError,
    URLNetlocError,
    URLPathError,
    URLSchemaError,
)
from wingpy.interfaces import ApiClient
from wingpy.logger import log_exception, logger
from wingpy.scheduling import RequestLogEntry, RequestThrottler, TaskRunner


@dataclass
class HttpResponsePattern:
    """
    Represents a specific HTTP response pattern for platform-specific handling.

    Used to define conditions for retries, special handling, or other custom logic
    based on HTTP response attributes.
    """

    status_codes: list[int]
    """HTTP response status codes."""

    methods: list[str]
    """HTTP request methods."""

    content_patterns: list[re.Pattern]
    """HTTP response content RegEx patterns"""


class RequireClassVarsMeta(ABCMeta):
    """
    This metaclass ensures that all subclasses of RestApiBaseClass
    define the required class variables.
    It checks for the presence of class variables in the class hierarchy
    and raises a TypeError if any required class variable is missing.

    This is similar to the behavior of the @abstractmethod decorator,
    but for class variables rather than instance methods.

    Examples
    --------
    from abc import ABC
    class MyBaseClass(ABC, metaclass=RequireClassVarsMeta):
        REQUIRED_VAR: ClassVar[str]
        OPTIONAL_VAR: ClassVar[str] = "default_value"

    class MyClass(MyBaseClass):
        REQUIRED_VAR = "value"
        OPTIONAL_VAR = "new_value"
    # This will work because MyClass defines the REQUIRED_VAR class variable.

    class MyClassWithoutRequiredVar(MyBaseClass):
        OPTIONAL_VAR = "new_value"
    # This will raise a TypeError because MyClassWithoutRequiredVar does not define
    """

    def __init__(cls, name, bases, namespace):
        super().__init__(name, bases, namespace)

        # Skip abstract base classes, the metaclass will be used only for
        # concrete classes that define the metaclass
        if getattr(cls, "__abstractmethods__", None):
            return

        # Required classvars variable
        required = {}

        # Collect class variables from all the inherited class bases in the
        # hierarchy and add them to the required class variables.
        # Loop over the current class instance bases
        for base in cls.__mro__:
            """
            Examples
            --------
            RestApiBaseClass.__mro__
                (wingpy.base.RestApiBaseClass, abc.ABC, object)
            
            CiscoFMC.__mro__
                (wingpy.cisco.fmc.CiscoFMC, wingpy.base.RestApiBaseClass, abc.ABC, object)
            """

            # Skip the object class (the "empty" base class of the class hierarchy)
            if base is object:
                continue

            required.update(get_type_hints(base))
            """ 
            Update the required class variables with the type hints of the current class base
            
            Examples
            --------
            get_type_hints(CiscoFMC)
                {'RETRY_RESPONSES': typing.ClassVar[list[wingpy.base.HttpResponsePattern]],
                 'MAX_CONNECTIONS': typing.ClassVar[int]}

            get_type_hints(RestApiBaseClass)
                {'RETRY_RESPONSES': typing.ClassVar[list[wingpy.base.HttpResponsePattern]],
                 'MAX_CONNECTIONS': typing.ClassVar[int]}


            This will allow multiple class bases to define separate class variables
            and the metaclass will ensure that all of them are defined in the current class.

            In the above example, however, the dict will stay the same as the CiscoFMC class
            does not define any new class variables nor does it have other bases than RestApiBaseClass.
            """

        # Check if the class variables without defaults are defined in the current class
        for var_name in required:
            # inspect the current class INSTANCE for class variables
            if not hasattr(cls, var_name):
                # and raise an error if they are not defined, to mimic the behavior of
                # the @abstractmethod decorator for class variables
                raise TypeError(f"{name} must define class variable '{var_name}'")


class RestApiBaseClass(ApiClient, metaclass=RequireClassVarsMeta):
    """
    An abstract base class for REST API clients.

    This class provides a common interface and functionality for interacting
    with REST APIs. It handles requests, headers, throttling, path parameters,
    logging, retries, errors and session lifetime.
    It also defines the abstract methods that must be implemented by clients.
    """

    RETRY_RESPONSES: ClassVar[list[HttpResponsePattern]]
    """
    HTTP status codes and response text that should trigger a retry.

    Some APIs have specific responses that require a retry, even if the status code is not 429.
    """

    MAX_CONNECTIONS: ClassVar[int]
    """
    The maximum number of concurrent connections opened to the API server.

    If the number is documented in official documentation,
    it should be used to limit the number of connections.
    In other cases we may need to limit the number of connections to avoid
    overwhelming the server or the client machine.
    """

    def __init__(
        self,
        *,
        base_url: str,
        verify: SSLContext | bool = True,
        backoff_initial: int = 1,
        backoff_multiplier: float = 2.0,
        retries: int = 3,
        auth_lifetime: int = 0,
        auth_refresh_percentage: float = 1,
        rate_limit_period: int = 0,
        rate_limit_max_requests: int = 0,
        headers: dict | None = None,
        timeout: int = 10,
    ):
        self._verify_base_url(base_url)
        self.base_url: str = base_url
        """
        A string containing the base URL of the API server.
        
        The base URL path must include:

         - Scheme (http / https)
         - Hostname / IP address
         - TCP port
         - Base path, if any (MUST NOT end with a `/`)

        Examples
        --------
        - https://api.example.com/api/v1
        - http://api.example.com:8080
        """

        self.auth_lifetime: int = auth_lifetime
        """
        The lifetime in seconds of authentication token.
        """

        self.auth_refresh_percentage: float = auth_refresh_percentage
        """
        The percentage of the authentication token lifetime at which the token should be refreshed.

        This is used to avoid token expiration during long-running requests.
        The value should be between 0 and 1.
        For example, if the token lifetime is 3600 seconds (1 hour) and the refresh percentage is 0.8,
        the token will be refreshed after 2880 seconds (48 minutes).
        """

        self.retries: int = retries
        """
        The number of times a request will be retried in case of failures.

        The first attempt is not counted as a retry.
        """

        self.verify: SSLContext | bool = verify
        """
        Controls the verification of the API server SSL certificate.

        It can simply be enabled or disabled using boolean values,
        or a custom SSLContext can be passed to the constructor to use a custom
        certificate authority.

        Examples
        --------
        
        - `True`: Verify the server's SSL certificate using the system's CA certificates.
        - `False`: Disable SSL certificate verification.
        - `ssl.create_default_context(cafile="my-custom-ca.pem")`: Use a custom CA certificate for verification.
        """

        self.headers: dict = headers or {}
        """
        A dictionary of HTTP headers to be sent with each request.
        These headers will be merged with any `headers` dict passed to an individual request.
        """

        self.request_index: int = 0
        """
        An index to keep track of the number of requests made.
        """

        self.client: httpx.Client | None = None
        """
        An httpx Client instance used to send requests to the API server.

        This client is created when the first request is made and is reused for all subsequent requests.
        The opened TCP connection is reused for multiple requests to the same server.
        """

        self.auth_timestamp: arrow.Arrow | None = None
        """
        A timestamp indicating when the authentication token was last refreshed.

        In combination with auth_lifetime and auth_refresh_percentage it is used
        to determine when the token should be refreshed again.
        """

        self.path_params: dict = {}
        """
        A dictionary of path parameters to be used in the API path of each request.

        These parameters will be merged with any `path_params` dict passed to the request.
        """

        if self.MAX_CONNECTIONS > 1:
            # Leave one connection for the main thread used for authentication and synchronous requests
            max_workers = self.MAX_CONNECTIONS - 1
        else:
            # If a maximum number of connections is not supported, just use a single worker
            max_workers = 1

        self.tasks: TaskRunner = TaskRunner(max_workers=max_workers)
        """
        Manages concurrent requests to the API server.
        
        The number of concurrent requests is limited by the MAX_CONNECTIONS property:
        
        - 1 connection is reserved for the main thread used for authentication and synchronous requests.
        - The remaining connections are used for concurrent requests.

        See Also
        --------
        [`wingpy.scheduling.TaskRunner`](https://wingpy.automation.wingmen.dk/api/scheduling/#wingpy.scheduling.TaskRunner)
            Schedule and run asynchronous tasks in parallel.
        
        """

        self.throttler: RequestThrottler = RequestThrottler(
            backoff_initial=backoff_initial,
            backoff_multiplier=backoff_multiplier,
            rate_limit_period=rate_limit_period,
            rate_limit_max_requests=rate_limit_max_requests,
        )
        """"
        Manages request throttling and rate limiting to the API server.
        """

        self.request_log: list[RequestLogEntry] = []
        """
        A list of requests made to the API server.

        Each entry contains the request URL, status code, and timestamp.
        """

        self.timeout: int = timeout
        """The timeout in seconds for each request to the API server."""

        self._auth_lock: threading.Lock = threading.Lock()
        """Allow only one thread to authenticate at a time."""

    @abstractmethod
    def _authenticate(self) -> httpx.Response:
        """
        Abstract method to authenticate with the API server.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def is_authenticated(self) -> bool:
        """
        Abstract method to check if the client is authenticated with the API server.

        Returns
        -------
        bool
            `True` if authenticated, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def get(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Abstract method to send a GET request to the API server.

        Applies any API-specific pre- or post-processing.
        """
        raise NotImplementedError

    @abstractmethod
    def post(
        self,
        path: str,
        *,
        data: str | dict | list | None,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Abstract method to send a POST request to the API server.

        Applies any API-specific pre- or post-processing.
        """
        raise NotImplementedError

    @abstractmethod
    def put(
        self,
        path: str,
        *,
        data: str | dict | list | None,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Abstract method to send a PUT request to the API server.

        Applies any API-specific pre- or post-processing.
        """
        raise NotImplementedError

    @abstractmethod
    def patch(
        self,
        path: str,
        *,
        data: str | dict | list | None,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Abstract method to send a PATCH request to the API server.

        Applies any API-specific pre- or post-processing.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Abstract method to send a DELETE request to the API server.

        Applies any API-specific pre- or post-processing.
        """
        raise NotImplementedError

    def authenticate(self) -> None:
        """
        Executes the API-specific authentication process and records timestamps
        for session tracking.

        Notes
        ----
        Authentication will automatically be carried out just-in-time.

        Only call this method directly if you need to authenticate proactively,
        outside of normal request flow.
        """

        # Authenticate
        logger.debug("Authenticating and recording token lifetime")
        auth_response = self._authenticate()

        # Record the time of authentication
        self.auth_timestamp = arrow.utcnow()

        self._after_auth(auth_response=auth_response)

    def _after_auth(self, *, auth_response: httpx.Response):
        """
        Overload this method to perform any actions after authentication.

        Parameters
        ----------

        auth_response
            The response from the authentication request.
            This can be used to extract any additional information needed after authentication.
        """
        pass

    def _prepare_request(
        self,
        method,
        path,
        timeout: int,
        params: dict,
        path_params: dict,
        headers: dict,
        data: str,
    ) -> httpx.Request:
        """
        Create headers, create query parameters, replace path parameters and build the URL.

        Parameters
        ----------

        method
            The HTTP method to use for the request (GET, POST, PUT, PATCH, DELETE).
        path
            The API endpoint path to send the request to.
        path_params
            A dictionary of path parameters to be used in the API path.
            Is merged with [`self.path_params`](https://wingpy.automation.wingmen.dk/api/base/#wingpy.base.RestApiBaseClass.path_params)

        headers
            A dictionary of HTTP headers to be sent with the request.
            Is merged with [`self.headers`](https://wingpy.automation.wingmen.dk/api/base/#wingpy.base.RestApiBaseClass.headers)

        Returns
        -------
        httpx.Request
            The prepared request object.
        """

        if path[0] != "/":
            raise ValueError(f"Path '{path}' does not begin with /")

        if isinstance(params, dict):
            params = params.copy()

        merged_headers = self.headers.copy()
        if isinstance(headers, dict):
            merged_headers.update(headers)

        if path_params is not None and not isinstance(path_params, dict):
            raise TypeError("path_params must be dictionary")

        merged_path_params = self.path_params.copy()
        if isinstance(path_params, dict):
            merged_path_params.update(path_params)

        if not isinstance(timeout, int):
            timeout = httpx.USE_CLIENT_DEFAULT

        url = self.build_url(path, path_params=merged_path_params)

        serialized_payload = self.serialize_payload(data=data)

        request = self.client.build_request(
            method,
            url,
            content=serialized_payload,
            headers=merged_headers,
            params=params,
            timeout=timeout,
        )
        return request

    def _send_single_request(
        self,
        *,
        request: httpx.Request,
        request_log_prefix: str,
        response_log_prefix: str,
        auth: httpx.Auth | None = None,
    ) -> tuple[httpx.Response, arrow.Arrow]:
        """
        Ensures synchronized logging and error handling while seding a request.

        Parameters
        ----------
        request
            The request object to be sent.
        request_log_prefix
            A string prefix for the request log entry.
        response_log_prefix
            A string prefix for the response log entry.
        auth
            The authentication object to be used for the request.

        Returns
        -------
        tuple[httpx.Response, arrow.Arrow]
            A tuple containing the response object and the request timestamp.
        """

        with self.tasks._lock:
            # Ensure no other threads have locked the client due to rate limiting or server errors
            pass

            # Ensure synchronized logging
            logger.trace(
                f"Prepared {request_log_prefix}: {request.method} {request.url}"
            )
            request_header_json = json.dumps(dict(request.headers))  # type: ignore[no-untyped-call]
            logger.trace(
                f"Prepared {request_log_prefix} headers: {request_header_json}"
            )
            logger.trace(f"Prepared {request_log_prefix} body: {request.content}")

        try:
            request_time = arrow.utcnow()
            response = self.client.send(request, auth=auth)  # type: ignore[no-untyped-call]
            # Log the response
            self.request_log.append(
                RequestLogEntry(
                    url=str(response.url),
                    status_code=response.status_code,
                    timestamp=arrow.utcnow(),
                ),
            )
        except httpx.RequestError as error:
            log_exception(error, severity="CRITICAL")
            raise error

        with self.tasks._lock:
            # Ensure synchronized logging
            logger.debug(f"{request_log_prefix}: {request.method} {request.url}")

            response_header_json = json.dumps(dict(response.headers))
            logger.trace(
                f"{response_log_prefix} status code: {response.status_code} {response.reason_phrase}"
            )
            logger.trace(f"{response_log_prefix} headers: {response_header_json}")
            logger.trace(f"{response_log_prefix} body: {response.text}")

        return response, request_time

    def _send_request_with_retry(
        self,
        request: httpx.Request,
        is_auth_endpoint: bool = False,
        auth: httpx.Auth | None = None,
    ) -> httpx.Response:
        """
        Send a request to the API server and handle special-case response.

        Handles retries, authentication headers and rate limiting.

        Parameters
        ----------
        request
            The request object to be sent.
        is_auth_endpoint
            A boolean indicating if the request is a dedicated authentication request.
            If `True`, the request is not retried on authentication failure.
        auth
            The authentication object to be used for the request.

        Returns
        -------
        httpx.Response
            The response object returned by the API server.
        """
        max_attempts = self.retries + 1
        attempt = 0
        self.request_index += 1
        request_index = self.request_index
        response: httpx.Response | None = None
        request_log_prefix = ""

        rate_limited_retry = False
        # Try at least once
        while attempt < max_attempts or rate_limited_retry:
            if not rate_limited_retry:
                attempt += 1

            attempt_log_suffix = f" (attempt {attempt})" if attempt > 1 else ""
            request_log_prefix = f"Request #{request_index}{attempt_log_suffix}"
            response_log_prefix = f"Response #{request_index}{attempt_log_suffix}"

            try:
                response, request_time = self._send_single_request(
                    request=request,
                    auth=auth,
                    request_log_prefix=request_log_prefix,
                    response_log_prefix=response_log_prefix,
                )
            except httpx.RemoteProtocolError:
                continue

            # Platform specific responses that require retry
            if self.is_retry_response(response, request.method):
                with self.tasks._lock:
                    logger.debug(
                        f"{response_log_prefix} invalid, requires retry: {response.status_code} {response.text}"
                    )
                    self.throttler.wait_for_backoff(start_time=request_time)

            # HTTP 429 Too Many Requests
            elif response.status_code == 429:
                with self.tasks._lock:
                    # Lock all other threads until the rate limit delay is over
                    logger.info(
                        f"{request_log_prefix} rate limited by API server (HTTP 429 Too Many Requests)"
                    )
                    self.throttler.wait_for_rate_limit(
                        start_time=request_time,
                        response=response,
                        request_log=self.request_log,
                    )
                    rate_limited_retry = True

            # HTTP 401 Unauthorized
            elif response.status_code == 401:
                self.throttler.reset_backoff()

                if is_auth_endpoint:
                    error = AuthenticationFailure(request_log_prefix, response=response)
                    log_exception(error, severity="CRITICAL")
                    raise error
                else:
                    return response

            elif response.status_code <= 399:
                self.throttler.reset_backoff()
                return response

            else:
                logger.error(
                    f"{request_log_prefix} failed with status code {response.status_code}"
                )
                return response
        error = httpx.HTTPStatusError(
            f"Max attempts reached for {request_log_prefix}",
            request=request,
            response=response,
        )
        log_exception(error, severity="ERROR")
        raise error

    def is_retry_response(self, response: httpx.Response, method: str) -> bool:
        result = False
        for retry_reponse in self.RETRY_RESPONSES:
            if (
                response.status_code in retry_reponse.status_codes
                and method in retry_reponse.methods
            ):
                for content_pattern in retry_reponse.content_patterns:
                    if content_pattern.match(response.content.decode()):
                        result = True
                        break
            if result:
                break
        return result

    def request(
        self,
        method: str,
        path: str,
        data: dict | list | etree._Element | str | None,
        params: dict,
        path_params: dict,
        headers: dict,
        timeout: int,
        is_auth_endpoint: bool,
        auth: httpx.Auth | None,
    ) -> httpx.Response:
        """
        Send any type of HTTP request and receive response.

        Handles any preprocessing of authentication, parameters, payload, and URL

        Parameters
        ----------
        method
            The HTTP method to use for the request (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`).

        path : str
            URL endpoint path. Is combined with [`self.base_url`](https://wingpy.automation.wingmen.dk/api/base/#wingpy.base.RestApiBaseClass.base_url)

        params : dict
            Query parameters to include in the request.

        path_params
            A dictionary of path parameters to be used in the API path.
            Is merged with [`self.path_params`](https://wingpy.automation.wingmen.dk/api/base/#wingpy.base.RestApiBaseClass.path_params)

        headers
            A dictionary of HTTP headers to be sent with the request.
            Is merged with [`self.headers`](https://wingpy.automation.wingmen.dk/api/base/#wingpy.base.RestApiBaseClass.headers)

        timeout : int
            Number of seconds to wait for HTTP responses before raising httpx.TimeoutException exception.

        is_auth_endpoint : bool
            A boolean indicating if the request is a dedicated authentication request.

            If `True`, authentication flow is skipped.

        auth : httpx.Auth | None
            The authentication object to be used for the request.

        Returns
        -------
        httpx.Response
            The response object returned by the API server.
        """

        # If the request is not an authentication request, make sure we have a valid token
        self._ensure_client()

        if not is_auth_endpoint:
            self._ensure_auth()

        request = self._prepare_request(
            method,
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            data=data,
        )

        return self._send_request_with_retry(
            request, is_auth_endpoint=is_auth_endpoint, auth=auth
        )

    def _verify_base_url(self, base_url: str) -> None:
        """
        Verifies the base URL contains a scheme, hostname, and does not end with a `/`.

        Parameters
        ----------
        base_url
            The base URL to be verified.

        Raises
        ------
        URLSchemaError
            If the base URL does not contain a scheme (http or https).
        URLNetlocError
            If the base URL does not contain a hostname or IP address.
        URLPathError
            If the base URL path ends with a `/`.
        """
        parsed_url = urlparse(base_url)
        if parsed_url.scheme.lower() not in ("http", "https"):
            error = URLSchemaError(base_url=base_url)
            log_exception(error, severity="ERROR")
            raise error
        if not parsed_url.netloc:
            error = URLNetlocError(base_url=base_url)
            log_exception(error, severity="ERROR")
            raise error
        if parsed_url.path and parsed_url.path[-1] == "/":
            error = URLPathError(base_url=base_url)
            log_exception(error, severity="ERROR")
            raise error

    def build_url(self, path: str, path_params: dict):
        """
        Constructs the full URL for a request.

        Combines the base URL with the provided path and substituting any path parameters.
        Path parameters are variables embedded into the URL path using {} braces.
        __Example:__ /organizations/{organizationId}/firmware/upgrades
        __Example:__ /api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{objectId}
        Reusable path parameters can be added to the class instance using the `path_params` attribute.
        Single-use path parameters can be passed as a dictionary to the `path_params` argument.

        Parameters
        ----------
        path
            The URL path, which may include placeholders for path parameters
            (e.g., "/organizations/{organizationId}/firmware/upgrades").

        path_params
            A dictionary of path parameters to be used in the API path.
            Is merged with [`self.path_params`](https://wingpy.automation.wingmen.dk/api/base/#wingpy.base.RestApiBaseClass.path_params).

        Returns
        -------
        str
            The fully constructed URL with all path parameters substituted.

        Raises
        ------

        MissingPathParameterError
            If the resulting URL contains unsubstituted path parameters.
        """

        # Merge reusable and single-use path parameters
        merged_path_params = self.path_params.copy()
        merged_path_params.update(path_params or {})

        # Replace path parameters in the URL and report any missing parameters
        # that are not in the path_params dictionary
        try:
            url = f"{self.base_url}{path}".format(**merged_path_params)
        except KeyError as e:
            missing_param = e.args[0]
            available_params = ", ".join(merged_path_params.keys())
            error = MissingPathParameterError(
                parameter=missing_param,
                available_params=available_params,
                endpoint_path=path,
                client=self,
            )
            log_exception(error, severity="ERROR")
            raise error

        return url

    def _ensure_client(self):
        """
        Instantiate a new `httpx` client if needed.

        Issues a warning if SSL verification is disabled.
        """

        if not self.client:
            limits = httpx.Limits(
                max_keepalive_connections=self.MAX_CONNECTIONS,
                max_connections=self.MAX_CONNECTIONS,
                keepalive_expiry=60,
            )

            if not self.verify:
                logger.warning(
                    f"Disabling SSL verification for {self.base_url} session"
                )
            self.client = httpx.Client(
                verify=self.verify,
                timeout=self.timeout,
                http2=False,
                limits=limits,
            )

    def _ensure_auth(self):
        """
        Verifies if the client is authenticated and refreshes the authentication token if needed.
        """
        # Authenticate if this is the first time
        with self._auth_lock:
            if self.auth_timestamp is None:
                logger.debug("No authentication token found")
                self.authenticate()
            else:
                # Refresh before the token expires after a percentage of the lifetime
                if self.auth_lifetime > 0:
                    refresh_after = self.auth_lifetime * self.auth_refresh_percentage
                    refresh_at = self.auth_timestamp.shift(seconds=refresh_after)
                    if arrow.utcnow() > refresh_at:
                        logger.debug("Authentication token expired")
                        self.authenticate()

    def close(self) -> None:
        """
        Close the httpx client and release any resources.
        This method should be called when the client is no longer needed.
        It is automatically called when exiting the context manager.
        """
        if self.client:
            self.client.close()
            logger.debug("Closed API client")
            self.client = None
            logger.debug("Client set to None")

    def __enter__(self):
        """
        When a context manager is used, this method is called to enter the runtime context.
        This method is called when the `with` statement is used with this class.

        Returns
        -------
        self
            The instance of the class itself.
        """
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        """
        This method is called when exiting the runtime context.
        It closes the client and handles any exceptions that occurred during the context.

        Parameters
        ----------
        exc_type
            The type of the exception that occurred, if any.
        exc_value
            The value of the exception that occurred, if any.
        traceback
            The traceback object of the exception that occurred, if any.

        Returns
        -------
        bool
            `False` to propagate the exception, `True` to suppress it. Always returns `False`.

            This ensures that any exceptions that occurred during the context are propagated.
        """
        self.close()
        if exc_type is not None:
            logger.error(f"Exception occurred: {exc_value}")
        # Return False to propagate the exception
        return False

    def serialize_payload(
        self, *, data: dict | list | etree._Element | str | None
    ) -> str:
        if isinstance(data, (dict, list)):
            json_data = json.dumps(data)
            return json_data
        elif isinstance(data, etree._Element):
            xml_data = etree.tostring(data)
            return xml_data
        elif isinstance(data, str):
            return data
        elif data is None:
            return ""
        else:
            raise ValueError(
                "Data for request payload must be provided as string, dict, list or lxml.etree.Element"
            )
