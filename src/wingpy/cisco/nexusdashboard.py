# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import os
from ssl import SSLContext

import httpx
from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import AuthenticationFailure, UnexpectedPayloadError
from wingpy.logger import log_exception, logger


class CiscoNexusDashboard(RestApiBaseClass):
    """
    Interact with the Cisco Nexus Dashboard API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_NEXUS_DASHBOARD_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_NEXUS_DASHBOARD_USERNAME`.

    authdomain : str | None, default=DefaultAuth
        Domain name for API authentication.

        Overrides the environment variable `WINGPY_NEXUS_DASHBOARD_USERNAME`.

    password : str | None, default=None
        Password for API authentication.
        Not supported together with `apikey`

        Overrides the environment variable `WINGPY_NEXUS_DASHBOARD_PASSWORD`

    apikey : str | None, default=None
        Key for API authentication.
        Not supported together with `password`

        Overrides the environment variable `WINGPY_NEXUS_DASHBOARD_APIKEY`

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
    from wingpy import CiscoNexusDashboard
    nexusdashboard = CiscoNexusDashboard(
        base_url="https://nd.example.com/api/v1/infra/",
        username="example_username",
        password="example_password",
    )
    nexusdashboard.get("/systemResources/summary")
    ```
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Cisco Nexus Dashboard.
    """

    MAX_CONNECTIONS = 20
    """
    The maximum number of concurrent connections opened to the Cisco Nexus Dashboard.
    
    1 connection will be used for general synchronous requests.
    
    6 connections will be used for parallel asynchronous requests.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        username: str | None = None,
        authdomain: str | None = None,
        apikey: str | None = None,
        password: str | None = None,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 3,
    ):
        # Allow parameters to be passed directly or fallback to environment variables
        self.nexusdashboard_url = base_url or os.getenv(
            "WINGPY_NEXUS_DASHBOARD_BASE_URL"
        )
        """
        The base URL for the Cisco Nexus Dashboard API.

        If not provided, it will be read from the environment variable `WINGPY_NEXUS_DASHBOARD_BASE_URL`.
        """

        self.username = username or os.getenv("WINGPY_NEXUS_DASHBOARD_USERNAME")
        """
        The username for authentication.
        If not provided, it will be read from the environment variable `WINGPY_NEXUS_DASHBOARD_USERNAME`.
        """

        self.password = password or os.getenv("WINGPY_NEXUS_DASHBOARD_PASSWORD")
        """
        The password for authentication.
        If not provided, it will be read from the environment variable `WINGPY_NEXUS_DASHBOARD_PASSWORD`.
        Not supported with `apikey`.
        """

        self.apikey = apikey or os.getenv("WINGPY_NEXUS_DASHBOARD_APIKEY")
        """
        The API key used for authentication.
        If not provided, it will be read from the environment variable `WINGPY_NEXUS_DASHBOARD_APIKEY`.
        Not supported with `password`.
        """

        if self.password and self.apikey:
            raise ValueError("Password and API key not supported simultaneously.")

        self.authdomain = (
            authdomain
            or os.getenv("WINGPY_NEXUS_DASHBOARD_AUTHDOMAIN")
            or "DefaultAuth"
        )
        """
        The name of the authentication domain for authentication.
        If not provided, it will be read from the environment variable `WINGPY_NEXUS_DASHBOARD_AUTHDOMAIN`.

        """

        self.token = None
        """
        The authentication token for the Cisco Nexus Dashboard API.
        """

        if not self.nexusdashboard_url:
            raise ValueError(
                "Cisco Nexus Dashboard base_url must be provided either as argument or environment variable"
            )

        self.version: Version = Version("0.0")
        """
        The version of the Cisco Nexus Dashboard API.
        """

        super().__init__(
            base_url=self.nexusdashboard_url,
            auth_lifetime=1200,
            auth_refresh_percentage=0.9,
            verify=verify,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=timeout,
            retries=retries,
        )

    def _authenticate(self) -> httpx.Response:
        """
        Retrieves and stores an `X-auth-token` cookie header by authenticating
        with the Cisco Nexus Dashboard API using the provided username and password.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`CiscoNexusDashboard.authenticate()`](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.authenticate)

        Returns
        -------
        httpx.Response
            The response object from the authentication request.
        """

        if not self.username:
            raise ValueError("Username must be provided for authentication")

        # Password based authentication
        if self.password:
            data = {
                "userName": self.username,
                "userPasswd": self.password,
                "domain": self.authdomain,
            }

            response = self.request(
                "POST",
                "/login",
                auth=None,
                is_auth_endpoint=True,
                data=data,
                params=None,
                path_params=None,
                headers=None,
                timeout=None,
            )

            self.token = response.json()["token"]
            self.headers["Cookie"] = f"AuthCookie={self.token}"
            return response

        # API key based authentication
        elif self.apikey:
            self.headers["X-Nd-Username"] = self.username
            self.headers["X-Nd-Apikey"] = self.apikey
            return

        # Key or password not supplied
        else:
            raise ValueError("Password or API key must be provided for authentication")

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return self.token is not None or self.apikey is not None

    def _after_auth(self, **kwargs) -> None:
        """
        Handle meta data retrieval after authentication.

        Raises
        ------
        AuthenticationFailure
            If no authentication token is available after authentication.
        """

        if not self.is_authenticated:
            error = AuthenticationFailure(
                message="No authentication token available after authentication."
            )
            log_exception(error)
            raise error

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
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

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
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

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
        data: str | dict | list | None,
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
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

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

    def patch(
        self,
        path: str,
        *,
        data: str | dict | list | None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Send an HTTP `PATCH` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : str | dict | list
            Request payload as JSON string or Python list/dict object.

        path_params : dict | None, default=None
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "PATCH",
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
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

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
        page_size: int = 10000,
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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

        page_size : int, default=500
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `response` key in the Cisco Nexus Dashboard API JSON responses.
        """

        logger.debug(f"Retrieving all pages from {path}")

        first_page = self.get_page(
            path,
            params=params,
            path_params=path_params,
            offset=0,
            limit=page_size,
        )

        json_response_data = first_page.json()

        total = json_response_data.get("meta", {}).get("counts", {}).get("total")

        if not isinstance(total, int):
            error = UnexpectedPayloadError(
                "Integer not found in meta.counts.total for paginated endpoint",
                response=first_page,
            )
            log_exception(error)
            raise error

        result_key = None

        for key, value in json_response_data.items():
            if isinstance(value, list):
                logger.trace(f"Using list with key '{key}' for page content")
                result_key = key
                break

        if not result_key:
            error = UnexpectedPayloadError(
                "No lists for pagination found in payload",
                response=first_page,
            )
            log_exception(error)
            raise error

        result: list = json_response_data[result_key]

        total_count = int(json_response_data["meta"]["counts"]["total"])

        logger.debug(f"Paging with {range(page_size, total_count, page_size) = }")

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
            print(len(page_response.json().get(result_key, [])))
            result += page_response.json().get(result_key, [])

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nexusdashboard/#wingpy.cisco.NexusDashboard.CiscoNexusDashboard.timeout) for a single request.

        Returns
        -------
        httx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        if isinstance(params, dict):
            params = params.copy()
        else:
            params = {}

        # Prepare params for the first page of data
        params["offset"] = offset
        params["max"] = limit

        rsp = self.get(
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        page = (offset // limit) + 1

        logger.debug(f"Retrieved page {page} from {path}.")

        return rsp
