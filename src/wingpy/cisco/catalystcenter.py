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
from wingpy.exceptions import AuthenticationFailure, UnsupportedMethodError
from wingpy.logger import log_exception, logger


class CiscoCatalystCenter(RestApiBaseClass):
    """
    Interact with the Cisco Catalyst Center API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_CATALYST_CENTER_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_CATALYST_CENTER_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_CATALYST_CENTER_PASSWORD`.

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
    from wingpy import CiscoCatalystCenter
    catalyst = CiscoCatalystCenter(
        base_url="https://sandboxdnac2.cisco.com",
        username="example_username",
        password="example_password",
    )
    catalyst.get("/dna/intent/api/v1/network-device")
    ```
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Cisco Catalyst Center.
    """

    MAX_CONNECTIONS = 7
    """
    The maximum number of concurrent connections opened to the Catalyst Center.
    
    1 connection will be used for general synchronous requests.
    
    6 connections will be used for parallel asynchronous requests.
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
        self.catalyst_url = base_url or os.getenv("WINGPY_CATALYST_CENTER_BASE_URL")
        """
        The base URL for the Catalyst Center API.

        If not provided, it will be read from the environment variable `WINGPY_CATALYST_CENTER_BASE_URL`.
        """

        self.username = username or os.getenv("WINGPY_CATALYST_CENTER_USERNAME")
        """
        The username for authentication.
        If not provided, it will be read from the environment variable `WINGPY_CATALYST_CENTER_USERNAME`.
        """

        self.password = password or os.getenv("WINGPY_CATALYST_CENTER_PASSWORD")
        """
        The password for authentication.
        If not provided, it will be read from the environment variable `WINGPY_CATALYST_CENTER_PASSWORD`.
        """

        self.token = None
        """
        The authentication token for the Catalyst Center API.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided either as argument or environment variable"
            )
        self.auth = httpx.BasicAuth(username=self.username, password=self.password)
        """
        The authentication object for the Catalyst Center API.
        """

        if not self.catalyst_url:
            raise ValueError(
                "Catalyst Center base_url must be provided either as argument or environment variable"
            )

        self.version: Version = Version("0.0")
        """
        The version of the Catalyst Center API.
        """

        super().__init__(
            base_url=self.catalyst_url,
            auth_lifetime=3600,
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
        with the Catalyst Center API using the provided username and password.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`CiscoCatalystCenter.authenticate()`](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.authenticate)

        Returns
        -------
        httpx.Response
            The response object from the authentication request.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided for authentication"
            )

        response = self.request(
            "POST",
            "/dna/system/api/v1/auth/token",
            auth=self.auth,
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
        )

        self.token = response.json()["Token"]
        self.headers["X-auth-token"] = self.token
        return response

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return self.token is not None

    def _after_auth(self, **kwargs) -> None:
        """
        Handle meta data retrieval after authentication.
        """

        if not self.is_authenticated:
            err = AuthenticationFailure("Authentication required before use")
            log_exception(err)
            raise err

        response = self.request(
            "GET",
            "/dna/intent/api/v1/dnac-release",
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            auth=None,
        )
        if response.status_code == 200:
            version = response.json().get("response", {}).get("installedVersion", "0.0")
            self.version = Version(version)
            logger.info(f"Catalyst Center version: {self.version} detected")
        else:
            logger.info("Unable to detect Catalyst Center version")

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

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
            auth=self.auth,
        )

        return response

    def patch(self, *args, **kwargs) -> None:  # ignore: type
        """
        !!! failure "HTTP PATCH is not supported by Catalyst Center"

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

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
            auth=self.auth,
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
        page_size: int = 500,
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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

        page_size : int, default=500
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `response` key in the Catalyst Center API JSON responses.
        """

        logger.debug(f"Retrieving all pages from {path}")

        result = []
        offset = 1

        while True:
            page = self.get_page(
                path,
                params=params,
                path_params=path_params,
                offset=offset,
                limit=page_size,
                headers=headers,
                timeout=timeout,
            )
            offset += page_size
            page_reponse = page.json()["response"]
            result += page_reponse

            if len(page_reponse) < page_size:
                logger.trace("Exiting pagination loop")
                break

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout) for a single request.

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
        params["limit"] = limit

        rsp = self.get(
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        page = (offset // limit) + 1

        page_reponse = rsp.json()["response"]
        if len(page_reponse) > 0:
            logger.debug(f"Successfully retrieved page {page} from {path}")
        else:
            logger.debug(f"Page {page} returned no items")

        return rsp
