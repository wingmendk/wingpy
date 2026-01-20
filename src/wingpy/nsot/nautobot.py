# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import os
from ssl import SSLContext

import httpx
from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import AuthenticationFailure, InvalidEndpointError
from wingpy.logger import log_exception, logger


class Nautobot(RestApiBaseClass):
    """
    Interact with the Nautobot API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_NAUTOBOT_BASE_URL`.

    token : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_NAUTOBOT_TOKEN`.

    verify : bool | SSLContext, default=True
        Boolean values will enable or disable the default SSL verification.

        Use an ssl.SSLContext to specify custom Certificate Authority.

    timeout : int, default=10
        Number of seconds to wait for HTTP responses before raising httpx.TimeoutException exception.

    retries : int, default=3
        Number of failed HTTP attempts allowed before raising httpx.HTTPStatusError exception.

    api_version: str | None, default=None
        Use a specific default version of the API using the HTTP Accept header.

    Examples
    --------
    ```python
    from wingpy import Nautobot
    nautobot = Nautobot(
        base_url="http://nautobot.example.com",
        token="0123456789abcdef0123456789abcdef01234567",
    )
    nautobot.get("/api/status/")
    ```
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Nautobot.
    """

    MAX_CONNECTIONS = 6
    """
    The maximum number of concurrent connections opened to the Nautobot.
    
    1 connection will be used for general synchronous requests.
    
    5 connections will be used for parallel asynchronous requests.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 3,
        api_version: str | None = None,
    ):
        # Allow parameters to be passed directly or fallback to environment variables
        self.nautobot_url = base_url or os.getenv("WINGPY_NAUTOBOT_BASE_URL")
        """
        The base URL for the Nautobot API.

        If not provided, it will be read from the environment variable `WINGPY_NAUTOBOT_BASE_URL`.
        """

        self.token = token or os.getenv("WINGPY_NAUTOBOT_TOKEN")
        """
        The API token for authentication.
        If not provided, it will be read from the environment variable `WINGPY_NAUTOBOT_TOKEN`.
        """

        if not self.token:
            raise ValueError(
                "API token must be provided either as argument or environment variable"
            )

        if not self.nautobot_url:
            raise ValueError(
                "Nautobot base_url must be provided either as argument or environment variable"
            )

        self.version: Version = Version("0.0")
        """
        The version of the Nautobot API.
        """

        self.api_version = api_version
        """
        Default Nautobot API version to request using the HTTP Accept header.
        """

        super().__init__(
            base_url=self.nautobot_url,
            verify=verify,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=timeout,
            retries=retries,
        )

        if api_version:
            logger.info(f"Setting default API version to {self.api_version}")
            self.headers["Accept"] += f"; version={self.api_version}"

    def _authenticate(self) -> None:
        """
        Prepares the HTTP headers for token based authentication.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`Nautobot.authenticate()`](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.authenticate)

        Returns
        -------
        httpx.Response
            The response object from the authentication request.
        """

        self.headers["Authorization"] = f"Token {self.token}"

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
            raise AuthenticationFailure(
                "Authentication required before use"
            )  # pragma: no cover

        response = self.request(
            "GET",
            "/api/status/",
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            auth=None,
        )

        if response.status_code == 200:
            version = response.json().get("nautobot-version", "0.0")
            self.version = Version(version)
            logger.info(f"Nautobot version: {self.version} detected")
        elif response.status_code == 403:
            error = AuthenticationFailure("Authentication failed", response=response)
            log_exception(error)
            raise error
        else:
            logger.info("Unable to detect Nautobot version")

    def _validate_path(self, path: str) -> None:
        if not path.startswith("/"):
            error = InvalidEndpointError("Nautobot endpoint paths must begin with /")
            log_exception(error)
            raise error
        if not path.endswith("/"):
            error = InvalidEndpointError("Nautobot endpoint paths must end with /")
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
        api_version: str | None = None,
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
            Replace placeholders like `{id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        self._validate_path(path)

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if api_version:
            logger.info(f"Setting API version to {api_version}")
            headers["Accept"] = f"application/json; version={api_version}"

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
        api_version: str | None = None,
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
            Replace placeholders like `{id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        self._validate_path(path)

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if api_version:
            logger.info(f"Setting API version to {api_version}")
            headers["Accept"] = f"application/json; version={api_version}"

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
        api_version: str | None = None,
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
            Replace placeholders like `{id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        self._validate_path(path)

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if api_version:
            logger.info(f"Setting API version to {api_version}")
            headers["Accept"] = f"application/json; version={api_version}"

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
        api_version: str | None = None,
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
            Replace placeholders like `{id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        self._validate_path(path)

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if api_version:
            logger.info(f"Setting API version to {api_version}")
            headers["Accept"] = f"application/json; version={api_version}"

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
        api_version: str | None = None,
    ) -> httpx.Response:
        """
        Send an HTTP `DELETE` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        path_params : dict | None, default=None
            Replace placeholders like `{id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        self._validate_path(path)

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if api_version:
            logger.info(f"Setting API version to {api_version}")
            headers["Accept"] = f"application/json; version={api_version}"

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
        page_size: int = 100,
        api_version: str | None = None,
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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        page_size : int, default=100
            The number of items to retrieve per page. Recommended maximum value: 1000.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `response` key in the Nautobot API JSON responses.
        """

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if api_version:
            logger.info(f"Setting API version to {api_version}")
            headers["Accept"] = f"application/json; version={api_version}"

        first_page = self.get_page(
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            offset=0,
            limit=page_size,
        )

        json_response_data = first_page.json()

        result: list = json_response_data.get("results", [])

        total_count = int(json_response_data.get("count", 0))

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
            result += page_response.json().get("results", [])

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
        api_version: str | None = None,
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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/nautobot/#wingpy.nsot.nautobot.Nautobot.timeout) for a single request.

        api_version: str | None, default=None
            Use a specific version of the API using the HTTP Accept header.

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

        page = offset // limit + 1

        page_reponse = rsp.json()["results"]
        if len(page_reponse) > 0:
            logger.debug(f"Successfully retrieved page {page} from {path}.")
        else:
            logger.debug(f"Page {page} returned no items.")

        return rsp
