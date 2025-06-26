# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

from ssl import SSLContext

import httpx
from lxml import etree

from wingpy.base import RestApiBaseClass


class GenericRESTAPI(RestApiBaseClass):
    """
    Interact with a generic REST API

    Examples
    --------
    ```python
    from wingpy import GenericRESTAPI
    client = GenericRESTAPI(base_url="https://httpbin.org")
    client.headers = {"Authorization": "Bearer my_token"}
    client.get("/bearer")
    ```
    """

    RETRY_RESPONSES = []

    MAX_CONNECTIONS = 1

    def __init__(
        self,
        *,
        base_url: str,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 3,
    ):
        # Allow parameters to be passed directly or fallback to environment variables

        self.generic_base_url = base_url
        """
        The BASE URL token for the generic API.
        """

        super().__init__(
            base_url=self.generic_base_url,
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

    def _authenticate(self) -> None:  # type: ignore[override]
        """
        No dedicated authentication is available for Generic.
        """
        pass

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return True

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
        params: dict | None = None,
        data: str | dict | list | etree._Element | None = None,
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

        data : str | dict | list | etree._Element | None, default=None
            Request payload as JSON string, Python list/dict object or XML Element.

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
            params=params,
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
        params: dict | None = None,
        data: str | dict | list | etree._Element | None = None,
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

        data : str | dict | list | etree._Element | None, default=None
            Request payload as JSON string, Python list/dict object or XML Element.

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
            params=params,
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
        params: dict | None = None,
        data: str | dict | list | etree._Element | None = None,
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

        data : str | dict | list | etree._Element | None, default=None
            Request payload as JSON string, Python list/dict object or XML Element.

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
            "PATCH",
            path,
            data=data,
            params=params,
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
        params: dict | None = None,
        data: str | dict | list | etree._Element | None = None,
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

        data : str | dict | list | etree._Element | None, default=None
            Request payload as JSON string, Python list/dict object or XML Element.

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
            data=data,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=None,
        )

        return response
