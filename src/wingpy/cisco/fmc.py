# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import math
import os
import re
from ssl import SSLContext
from urllib.parse import urlparse

import httpx
from packaging.version import Version

from wingpy.base import HttpResponsePattern, RestApiBaseClass
from wingpy.exceptions import UnsupportedMethodError
from wingpy.logger import log_exception, logger


class CiscoFMC(RestApiBaseClass):
    """
    Interact with the Cisco Secure Firewall Management Center (FMC) API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_FMC_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_FMC_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_FMC_PASSWORD`.

    verify : SSLContext | bool, default=True
        Boolean values will enable or disable the default SSL verification.

        Use an ssl.SSLContext to specify custom Certificate Authority.

    timeout : int, default=10
        Number of seconds to wait for HTTP responses before raising httpx.TimeoutException exception.

    retries : int, default=3
        Number of failed HTTP attempts allowed before raising httpx.HTTPStatusError exception.


    Examples
    --------
    ```python
    from wingpy import CiscoFMC
    fmc = CiscoFMC(
        base_url="https://fmc.example.com",
        username="admin",
        password="password",
        verify=False
    )
    fmc.get_all("/api/fmc_config/v1/domain/{domainUUID}/object/hosts")
    ```
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to the FMC.

    According to FMC documentation, a maximum of 10 concurrent
    connections from the same source IP address are supported.
    
    1 connection will be used for general synchronous requests.
    
    9 connections will be used for parallel asynchronous requests.
    """

    RETRY_RESPONSES = [
        HttpResponsePattern(
            status_codes=[200], methods=["GET"], content_patterns=[re.compile(r"{}")]
        ),
        HttpResponsePattern(
            status_codes=[500],
            methods=["GET", "POST", "PUT", "DELETE"],
            content_patterns=[
                re.compile(
                    r'{"error":{"category":"OTHER","messages":\[{}\],"severity":"ERROR"}}'
                ),
                re.compile(
                    r'{"error":{"category":"FRAMEWORK","messages":\[{"description":"The action type is null"}\],"severity":"ERROR"}}'
                ),
            ],
        ),
        HttpResponsePattern(
            status_codes=[504],
            methods=["GET", "POST", "PUT", "DELETE"],
            content_patterns=[
                re.compile(
                    r'{"error":{"category":"FRAMEWORK","messages":\[{"description":"Request Timed Out\. Retry after sometime."}\],"severity":"ERROR"}}'
                )
            ],
        ),
    ]
    """
    The standard `HTTP 429` status code indicates that the user has sent
    too many requests in a given amount of time, and is being rate limited.

    When under heavy load, Cisco FMC will in some cases send back
    other responses with invalid payloads, instead of the standard
    `HTTP 429` status code.

    These responses will be retried until properly rate limited or
    a valid response is received.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 3,
    ):
        # Allow parameters to be passed directly or fallback to environment variables

        self.fmc_url = base_url or os.getenv("WINGPY_FMC_BASE_URL")
        """
        The base URL for the FMC API.
        
        Examples
        --------
        - https://fmc.example.com
        - https://192.0.2.1:8443
        """

        self.username = username or os.getenv("WINGPY_FMC_USERNAME")
        """
        The username for authentication to the FMC API.
        """

        self.password = password or os.getenv("WINGPY_FMC_PASSWORD")
        """
        The password for authentication to the FMC API.
        """

        if not self.fmc_url or not self.username or not self.password:
            raise ValueError(
                "FMC base_url, username and password must be provided either as arguments or environment variables"
            )

        super().__init__(
            base_url=self.fmc_url,
            auth_lifetime=1800,
            auth_refresh_percentage=0.9,
            verify=verify,
            rate_limit_period=60,
            rate_limit_max_requests=120,
            timeout=timeout,
            retries=retries,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        self.version: Version | None = None
        """
        The version of the FMC API.
        """

        self._token: str | None = None
        """
        The current token for the FMC API.
        """

    def _authenticate(self) -> httpx.Response:
        """
        Warnings
        --------
        Protected methods. Should only be called from inside the class itself.

        To authenticate on-demand use `.authenticate()`

        See Also
        --------
        [`wingpy.RestApiBaseClass.authenticate`](https://wingpy.automation.wingmen.dk/api/restapi/#wingpy.base.RestApiBaseClass.authenticate)
            Authenticate on-demand.

        Returns
        -------
        httpx.Response
            The response object from the authentication request.
        """

        parsed_url = urlparse(self.base_url)

        logger.info(
            f"Authenticating with FMC {parsed_url.netloc} as user: {self.username}"
        )

        # Authenticate with FMC using basic auth to obtain an access token
        response = self.request(
            "POST",
            "/api/fmc_platform/v1/auth/generatetoken",
            timeout=None,
            headers=None,
            params=None,
            path_params=None,
            data=None,
            auth=httpx.BasicAuth(username=self.username, password=self.password),  # type: ignore
            is_auth_endpoint=True,
        )
        response.raise_for_status()

        auth_headers = response.headers
        self._token = auth_headers.get("X-auth-access-token")

        if response.status_code == 204:
            # Successful authentication response
            self.headers["X-auth-access-token"] = self._token
        else:  # pragma: no cover
            raise Exception(
                f"Unexpected response code for authentication: {response.status_code}"
            )
        return response

    @property
    def is_authenticated(self) -> bool:
        """
        Check if the client is authenticated.
        """

        return self._token is not None

    def _after_auth(self, *, auth_response: httpx.Response) -> None:
        """
        Protected method. Should only be called from inside the class itself.

        Retrieves the FMC version and adjusts rate limiting accordingly.

        Warnings
        --------
        Should only be called from inside the class itself.

        Notes
        -----
        Extracts the Domain UUID from the authentication response headers and sets it
        as a path parameter for subsequent requests, since most FMC endpoints require it.
        Also retrieves the FMC version and adjusts the rate limit based on the version.

        Parameters
        ----------
        auth_response
            The response object from the authentication request.

        """

        # Most FMC endpoints require the domain UUID to be passed in the path parameters
        # e.g. /api/fmc_config/v1/domain/{domainUUID}/object/hosts
        self.path_params["domainUUID"] = auth_response.headers.get("DOMAIN_UUID")

        # Record the FMC version
        response = self.request(
            "GET",
            "/api/fmc_platform/v1/info/serverversion",
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            auth=None,
        )

        if response.status_code == 200:
            version_string = response.json()["items"][0]["serverVersion"]

            version_elements = version_string.split(" (")
            if len(version_elements) != 2:  # pragma: no cover
                raise ValueError(
                    f"Unexpected version string format: {version_string}. Expected format: 'version (build)'"
                )

            self.version = Version(version_elements[0])

            # Adjust the rate limit based on the FMC version
            if self.version >= Version("7.6"):
                self.throttler.rate_limit_max_requests = 300
            else:
                self.throttler.rate_limit_max_requests = 120  # pragma: no cover
            logger.info(
                f"FMC version: {self.version} detected, expected rate limit: {self.throttler.rate_limit_max_requests} requests per minute"
            )
        else:
            logger.info("Unable to detect FMC version")

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
        Send an HTTP `GET` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.path_params) before sending request.

            Note: `{domainUUID}` will be implicitly substituted with the default FMC domain.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "GET",
            path,
            data=None,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=None,
        )
        return response

    def post(
        self,
        path: str,
        *,
        data: dict | str,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        auth: httpx.Auth | None = None,
        is_auth_endpoint: bool = False,
    ) -> httpx.Response:
        """
        Send an HTTP `POST` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : dict | str
            Request payload as JSON string or Python dict.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.path_params) before sending request.

            Note: `{domainUUID}` will be implicitly substituted with the default FMC domain.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.timeout) for a single request.

        Other parameters
        ----------------
        auth : httpx.Auth | None, default=None
            Override the standard Authorization header.

        is_auth_endpoint : bool, default=False
            Disables the authentication flow for this request.

            Disables retries to prevent lockouts on failed authentication.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "POST",
            path,
            data=data,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            auth=auth,
            is_auth_endpoint=is_auth_endpoint,
        )
        return response

    def put(
        self,
        path: str,
        *,
        data: dict | str,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Send an HTTP `PUT` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : dict | str
            Request payload as JSON string or Python dict.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.path_params) before sending request.

            Note: `{domainUUID}` will be implicitly substituted with the default FMC domain.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "PUT",
            path,
            data=data,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            auth=None,
            is_auth_endpoint=None,
        )
        return response

    def patch(self, *args, **kwargs):
        """
        !!! failure "HTTP PATCH is not supported by FMC"

        Raises
        ------
        UnsupportedMethodError
        """
        error = UnsupportedMethodError(client=self, method="PATCH")
        log_exception(error)
        raise error

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
        Send an HTTP `DELETE` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.path_params) before sending request.

            Note: `{domainUUID}` will be implicitly substituted with the default FMC domain.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "DELETE",
            path,
            data=None,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            auth=None,
            is_auth_endpoint=None,
        )
        return response

    def get_all(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        expanded: bool = False,
        page_size: int = 1000,
    ) -> list:
        """
        Retrieves all pages of data from a `GET` endpoint using maximum concurrency.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.path_params) before sending request.

            Note: `{domainUUID}` will be implicitly substituted with the default FMC domain.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.timeout) for a single request.

        expanded : bool, default=False
            Whether to expand the returned resources with more details.
            This is a common option for all paginated GET endpoints in FMC.

        page_size : int, default=1000
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `items` key in the FMC API JSON responses.
        """

        logger.debug(f"Retrieving all pages from {path}")

        first_page = self.get_page(
            path,
            params=params,
            path_params=path_params,
            offset=0,
            limit=page_size,
            expanded=expanded,
        )

        json_response_data = first_page.json()

        result: list = json_response_data.get("items", [])

        total_count = int(json_response_data["paging"]["count"])

        logger.debug(
            f"Paging with {range(page_size, total_count, page_size) = } = {list(range(page_size, total_count, page_size))}"
        )

        # Prepare the pages to be retrieved in parallel
        for offset in range(page_size, total_count, page_size):
            self.tasks.schedule(
                self.get_page,
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
                offset=offset,
                limit=page_size,
            )

        page_responses = self.tasks.run()

        for page_response in page_responses.values():
            result += page_response.json().get("items", [])

        logger.debug(f"Received {len(result)} items from {path}")

        return result

    def get_page(
        self,
        path: str,
        offset: int,
        limit: int,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        expanded: bool = False,
    ) -> httpx.Response:
        """
        Retrieves a specific page of data from a `GET` endpoint.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        offset : int
            Index of first items of the page.

        limit : int
            The number of items to retrieve per page.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.path_params) before sending request.

            Note: `{domainUUID}` will be implicitly substituted with the default FMC domain.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.fmc.CiscoFMC.timeout) for a single request.

        expanded : bool, default=False
            Whether to expand the returned resources with more details.
            This is a common option for all paginated GET endpoints in FMC.

        Returns
        -------
        httx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        if isinstance(params, dict):
            params = params.copy()
        else:
            params = {}

        # All paginated GET endpoints in FMC have an option to expand the returned resources with more details
        params["expanded"] = expanded

        # Prepare params for the first page of data
        params["offset"] = offset
        params["limit"] = limit

        rsp = self.get(
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        json_response_data = rsp.json()

        if "paging" not in json_response_data.keys():  # pragma: no cover
            # Invalid response payload
            raise KeyError(
                f'Paginated response payload is expected to have an "paging" key. Available keys: {json_response_data.keys()}'
            )

        if "count" not in json_response_data["paging"].keys():  # pragma: no cover
            # Invalid response payload
            raise KeyError(
                f'"paging" is expected to have an "count" key. Available keys: {json_response_data["paging"]}'
            )

        total_count = int(json_response_data["paging"]["count"])

        total_pages = math.ceil(total_count / limit)

        page = offset // (limit + 1) + 1

        logger.debug(f"Successfully retrieved page {page} of {total_pages} from {path}")

        return rsp
