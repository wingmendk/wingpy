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
from wingpy.exceptions import InvalidResponseError, UnsupportedMethodError
from wingpy.logger import log_exception


class CiscoMerakiDashboard(RestApiBaseClass):
    """
    Interact with the Cisco Meraki Dashboard API.

    Parameters
    ----------
    token : str | None, default=None
        Bearer token for API authentication.

        Overrides the environment variable `WINGPY_MERAKI_DASHBOARD_TOKEN`.

    org_name : str | None, default=None
        Default organization name.

        Overrides the environment variable `WINGPY_MERAKI_DASHBOARD_ORG_NAME`.

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
    from wingpy import CiscoMerakiDashboard
    merakidashboard = CiscoMerakiDashboard(
        token=" ",
    )
    merakidashboard.get("/devices")
    ```

    Warnings
    --------
    Not all requests to Meraki Dashboard are suitable for concurrency.
    Examples include `DELETE /networks/{networkId}` and
    `POST /organizations/{organizationId}/networks/combine`.

    For those endpoints, it is recommended to use single-treading for
    maximum performance.
    """

    RETRY_RESPONSES = [
        HttpResponsePattern(
            status_codes=[400],
            methods=["DELETE"],
            content_patterns=[
                re.compile(
                    r'{"errors":\["Unable to destroy network N_\d+. This may be due to concurrent requests to delete or combine networks\."\]}'
                )
            ],
        )
    ]
    """
    The standard `HTTP 429` status code indicates that the user has sent
    too many requests in a given amount of time, and is being rate limited.

    For certain endpoints that require asynchronous background processing by
    Cisco Meraki Dashboard a `HTTP 400` will be returned instead.

    These responses will be retried.
    """

    MAX_CONNECTIONS = 4
    """
    The maximum number of concurrent connections opened to Meraki Dashboard.
    
    1 connection will be used for general synchronous requests.
    
    3 connections will be used for parallel asynchronous requests.
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        org_name: str | None = None,
        network_name: str | None = None,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 10,
    ):
        self.meraki_dashboard_base_url = "https://api.meraki.com/api/v1"
        """The base URL for the Meraki Dashboard API."""

        # Allow parameters to be passed directly or fallback to environment variables

        self.token = token or os.getenv("WINGPY_MERAKI_DASHBOARD_TOKEN")
        """
        The bearer token for authenticating to the Meraki Dashboard API.

        If not provided, it will be read from the environment variable `WINGPY_MERAKI_DASHBOARD_TOKEN`.
        """

        self.meraki_dashboard_org_name = org_name or os.getenv(
            "WINGPY_MERAKI_DASHBOARD_ORG_NAME"
        )
        """
        Default organization name.

        If not provided, it will be read from the environment variable `WINGPY_MERAKI_DASHBOARD_ORG_NAME`.
        """

        self.meraki_dashboard_network_name = network_name
        """
        Default network name
        """

        if not self.token:
            raise ValueError(
                "Meraki Dashboard token must be provided either as arguments or environment variables"
            )

        super().__init__(
            base_url=self.meraki_dashboard_base_url,
            auth_lifetime=0,
            auth_refresh_percentage=0,
            verify=verify,
            rate_limit_period=0,
            rate_limit_max_requests=0,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            backoff_multiplier=1.1,
            timeout=timeout,
            retries=retries,
        )

    def _authenticate(self) -> None:  # type: ignore
        """
        No dedicated authentication is available for Meraki Dashboard.
        """
        self.headers["Authorization"] = f"Bearer {self.token}"

    def _after_auth(self, *, auth_response):
        if self.meraki_dashboard_org_name:
            self.path_params.pop("organizationId", None)
            response = self.request(
                "GET",
                "/organizations",
                data=None,
                params=None,
                path_params=None,
                headers=None,
                timeout=None,
                auth=None,
                is_auth_endpoint=True,
            )
            for org in response.json():
                if org["name"] == self.meraki_dashboard_org_name:
                    self.path_params["organizationId"] = org["id"]
                    break

            if "organizationId" not in self.path_params.keys():
                raise ValueError(
                    f"Organization '{self.meraki_dashboard_org_name}' not found."
                )

        if self.meraki_dashboard_network_name:
            if "organizationId" not in self.path_params.keys():
                raise ValueError(
                    "Can't find default network without organization name."
                )

            self.path_params.pop("networkId", None)

            response = self.request(
                "GET",
                "/organizations/{organizationId}/networks",
                data=None,
                params=None,
                path_params=None,
                headers=None,
                timeout=None,
                auth=None,
                is_auth_endpoint=True,
            )
            for network in response.json():
                if network["name"] == self.meraki_dashboard_network_name:
                    self.path_params["networkId"] = network["id"]
                    break

            if "networkId" not in self.path_params.keys():
                raise ValueError(
                    f"Network '{self.meraki_dashboard_network_name}' not found in organization ID '{self.path_params['organizationId']}'."
                )

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
        params: dict[str, str | list[str]] | None = None,
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

        params : dict[str, str | list[str]] | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

            Some Meraki Dashboard API endpoints have query parameters where the value data type is "array of strings",
            ie. `productTypes` with the `/organizations/{organizationId}/networks` API endpoint.

            In those cases, the Meraki Dashboard API server expects the query parameter name to end with `[]`.

            Example: `params={"productTypes[]": ["switch", "camera"]}`

        path_params : dict | None, default=None
            Replace placeholders like `{fabricId}` in the URL path with actual values.

            Will be combined with [`self.path_params`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.path_params] before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [`self.headers`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.headers] before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [`self.timeout`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.timeout] for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.

        Raises
        ------
        ValueError
            If a query parameter value is a list but the parameter name does not end with `[]
        """

        if isinstance(params, dict):
            for param_key, param_value in params.items():
                if isinstance(param_value, list) and param_key[-2:] != "[]":
                    raise ValueError(
                        f"Invalid query parameter name for 'list of strings'. List based query parameter names must end with []. I.e. {param_key}[] instead of {param_key}"
                    )

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

            Will be combined with [`self.path_params`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.path_params] before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [`self.headers`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.headers] before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [`self.timeout`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.timeout] for a single request.

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

            Will be combined with [`self.path_params`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.path_params] before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [`self.headers`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.headers] before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [`self.timeout`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.timeout] for a single request.

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
        !!! failure "HTTP PATCH is not supported by Meraki Dashboard"

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

            Will be combined with [`self.path_params`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.path_params] before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [`self.headers`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.headers] before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [`self.timeout`][wingpy.cisco.merakidashboard.CiscoMerakiDashboard.timeout] for a single request.

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
        params: dict[str, str | list[str]] | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int | None = None,
    ) -> list:
        """
        Retrieves all pages of data from a JSON endpoint.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict[str, str | list[str]] | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

            Some Meraki Dashboard API endpoints have query parameters where the value data type is "array of strings",
            ie. `productTypes` with the `/organizations/{organizationId}/networks` API endpoint.

            In those cases, the Meraki Dashboard API server expects the query parameter name to end with `[]`.

            Example: `params={"productTypes[]": ["switch", "camera"]}`

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [`self.path_params`][wingpy.cisco.catalystcenter.CiscoCatalystCenter.path_params] before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [`self.headers`][wingpy.cisco.catalystcenter.CiscoCatalystCenter.headers] before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [`self.timeout`][wingpy.cisco.catalystcenter.CiscoCatalystCenter.timeout] for a single request.

        page_size : int | None, default=None
            Set a specific page size. Default value varies on the server side per API endpoint.

        Returns
        -------
        list[dict]
            A list of dictionaries, similar to the endpoint-specific key in the JSON responses.
        """

        merged_params = {}

        if isinstance(params, dict):
            merged_params.update(params)

        if page_size:
            merged_params["perPage"] = page_size

        first_page = self.get(
            path=path,
            params=merged_params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        result = first_page.json()

        # Meraki Dashboard returns empty responses as a dict instead of list
        if not isinstance(result, list):
            return []

        link_header = first_page.headers.get("link", "")

        while "rel=next" in link_header:
            matches = re.findall(r"<(\S+?)>; rel=(\S+?)(?:,|$)", link_header)
            next_url = None
            for url, rel in matches:
                if rel == "next":
                    next_url = url

            if next_url is None or self.base_url not in next_url:
                error = InvalidResponseError(
                    message="Pagination error: valid 'next' page URL not found in link header.",
                    response=first_page,
                )
                log_exception(error)
                raise error

            if self.base_url != next_url[: len(self.base_url)]:  # pragma: nocover
                error = InvalidResponseError(
                    message="Pagination error: 'next' page URL not part of the same API as the base URL.",
                    response=first_page,
                )
                log_exception(error)
                raise error

            next_path = next_url[len(self.base_url) :]

            page = self.get(
                path=next_path,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
            )

            result += page.json()

            link_header = page.headers.get("link", "")

        return result
