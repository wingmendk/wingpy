# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import os
import re
from ssl import SSLContext

import httpx

from wingpy.base import HttpResponsePattern, RestApiBaseClass
from wingpy.exceptions import UnsupportedMethodError
from wingpy.logger import log_exception


class CiscoHyperfabric(RestApiBaseClass):
    """
    Interact with the Cisco Hyperfabric API.

    Parameters
    ----------
    token : str | None, default=None
        Bearer token for API authentication.

        Overrides the environment variable `WINGPY_HYPERFABRIC_TOKEN`.

    verify : bool | SSLContext, default=True
        Boolean values will enable or disable the default SSL verification.

        Use an ssl.SSLContext to specify custom Certificate Authority.

    timeout : int, default=10
        Number of seconds to wait for HTTP responses before raising httpx.TimeoutException exception.

    retries : int, default=3
        Number of failed HTTP attempts allowed before raising httpx.HTTPStatusError exception.

    Examples
    --------
    ```python
    from wingpy import CiscoHyperfabric
    hyperfabric = CiscoHyperfabric(
        token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    )
    hyperfabric.get("/devices")
    ```
    """

    RETRY_RESPONSES = [
        HttpResponsePattern(
            status_codes=[500],
            methods=["GET", "POST", "PUT", "DELETE"],
            content_patterns=[
                re.compile(
                    r'{\n "message":  "resource limit exceeded. Please retry later",\n "field":  "orgLimit",\n "value":  "\d+",\n "status":  500,\n "errCode":  "ERR_CODE_NO_KNOWN_CODE",\n "trackingId":  "[0-9a-z\-]{36}"\n}'
                )
            ],
        ),
    ]
    """
    Parallel requests to the same organization may trigger error messages instead of HTTP status code 429.
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to Hyperfabric.
    
    1 connection will be used for general synchronous requests.
    
    9 connections will be used for parallel asynchronous requests.
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 3,
    ):
        self.hyperfabric_base_url = "https://hyperfabric.cisco.com/api/v1"
        """The base URL for the Hyperfabric API."""

        # Allow parameters to be passed directly or fallback to environment variables

        self.token = token or os.getenv("WINGPY_HYPERFABRIC_TOKEN")
        """
        The bearer token for authenticating to the Hyperfabric API.

        If not provided, it will be read from the environment variable `WINGPY_HYPERFABRIC_TOKEN`.
        """

        if not self.token:
            raise ValueError(
                "Hyperfabric token must be provided either as arguments or environment variables"
            )

        super().__init__(
            base_url=self.hyperfabric_base_url,
            auth_lifetime=0,
            auth_refresh_percentage=0,
            verify=verify,
            rate_limit_period=0,
            rate_limit_max_requests=0,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=timeout,
            retries=retries,
        )

    def _authenticate(self) -> None:  # type: ignore
        """
        No dedicated authentication is available for Hyperfabric.
        """
        self.headers["Authorization"] = f"Bearer {self.token}"

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return self.token is not None

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
            Replace placeholders like `{fabricId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.timeout) for a single request.

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
        data: str | dict | list | None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Send an HTTP `POST` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : str | dict | list | None
            Request payload as JSON string or Python list/dict object.

        path_params : dict | None, default=None
            Replace placeholders like `{fabricId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "POST",
            path,
            data=data,
            params=None,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=None,
        )

        return response

    def put(
        self,
        path: str,
        *,
        data: str | dict | list,
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

        data : str | dict | list
            Request payload as JSON string or Python list/dict object.

        path_params : dict | None, default=None
            Replace placeholders like `{fabricId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "PUT",
            path,
            data=data,
            params=None,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=None,
        )

        return response

    def patch(self, *args, **kwargs) -> None:  # ignore: type
        """
        !!! failure "HTTP PATCH is not supported by Hyperfabric"

        Raises
        ------
        UnsupportedMethodError
        """
        error = UnsupportedMethodError(method="PATCH", client=self)
        log_exception(error)
        raise error

    def delete(
        self,
        path: str,
        *,
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

        path_params : dict | None, default=None
            Replace placeholders like `{fabricId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.hyperfabric.CiscoHyperfabric.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "DELETE",
            path,
            data=None,
            params=None,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=None,
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
    ) -> list:
        """
        Retrieves all pages of data from a JSON endpoint.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

        Warnings
        --------
        The Cisco Hyperfabric API does not support pagination,
        so only a limited number of results are returned.

        Returns
        -------
        list[dict]
            A list of dictionaries, similar to the endpoint-specific key in the JSON responses.
        """
        response = self.get(path=path, params=params, path_params=path_params)

        json_response_data = response.json()

        if json_response_data:
            items: list = next(iter(json_response_data.values()))
        else:
            items = []
        return items
