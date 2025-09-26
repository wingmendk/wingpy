# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import os
import re
from ssl import SSLContext
from urllib.parse import urlencode

import httpx
from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import (
    AuthenticationFailure,
    UnexpectedPayloadError,
    UnsupportedMethodError,
)
from wingpy.logger import log_exception, logger


class CiscoVmanage(RestApiBaseClass):
    """
    Interact with the Cisco SD-WAN vManage API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`. Must end with `/dataservice`

        Overrides the environment variable `WINGPY_VMANAGE_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_VMANAGE_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_VMANAGE_PASSWORD`.

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
    from wingpy import CiscoVmanage
    vmanage = CiscoVmanage(
        base_url="https://sandbox-sdwan-2.cisco.com/dataservice",
        username="example_username",
        password="example_password",
    )
    vmanage.get("/")
    ```

    Raises
    ------
    ValueError
        When base_url, username or password is missing

    ValueError
        When base_url does not end with `/dataservice`
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Cisco SD-WAN vManage.
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to the Cisco SD-WAN vManage.
    
    1 connection will be used for general synchronous requests.
    
    9 connections will be used for parallel asynchronous requests.
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
        self.vmanage_url = base_url or os.getenv("WINGPY_VMANAGE_BASE_URL")
        """
        The base URL for the Cisco SD-WAN vManage API.

        If not provided, it will be read from the environment variable `WINGPY_VMANAGE_BASE_URL`.
        """

        self.username = username or os.getenv("WINGPY_VMANAGE_USERNAME")
        """
        The username for authentication.
        If not provided, it will be read from the environment variable `WINGPY_VMANAGE_USERNAME`.
        """

        self.password = password or os.getenv("WINGPY_VMANAGE_PASSWORD")
        """
        The password for authentication.
        If not provided, it will be read from the environment variable `WINGPY_VMANAGE_PASSWORD`.
        """

        self.xsrftoken = None
        """
        The XSRF token for the Cisco SD-WAN vManage API.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided either as argument or environment variable"
            )

        if not self.vmanage_url:
            raise ValueError(
                "Cisco SD-WAN vManage base_url must be provided either as argument or environment variable"
            )
        elif not self.vmanage_url.endswith("/dataservice"):
            raise ValueError("Cisco SD-WAN vManage base_url must end with /dataservice")

        self.version: Version = Version("0.0")
        """
        The version of the Cisco SD-WAN vManage API.
        """

        super().__init__(
            base_url=self.vmanage_url,
            auth_lifetime=1800,
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
        Retrieves and stores `JSESSIONID` cookie and X-XSRF-TOKEN heade by authenticating
        with the Cisco SD-WAN vManage API using the provided username and password.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`CiscoVmanage.authenticate()`](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.authenticate)

        Returns
        -------
        httpx.Response
            The response object from the authentication request.

        Raises
        ------
        ValueError
            When username or password is missing

        UnexpectedPayloadError
            When authentication failes with an unexpected repsonse.

        AuthenticationFailure
            When authentication fails with an error message or when a JSESSIONID cookie or X-XSRF-TOKEN header is missing.

        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided for authentication"
            )

        auth_payload = urlencode(
            {"j_username": self.username, "j_password": self.password}
        )

        auth_headers = {"Content-Type": "application/x-www-form-urlencoded"}

        # Temprarily disable base path
        base_path = "/dataservice"
        self.base_url = self.base_url[: -len(base_path)]

        response = self.request(
            "POST",
            "/j_security_check",
            auth=None,
            is_auth_endpoint=True,
            data=auth_payload,
            params=None,
            path_params=None,
            headers=auth_headers,
            timeout=None,
        )

        # Re-enable base path
        self.base_url += base_path

        # Successful auth returns empty response. Anything else is also 200 OK, but with payload content
        if len(response.content) > 0:
            try:
                error_details = response.json()["error"]
                error_msg = f"{error_details['message']}: {error_details['code']} {error_details['details']}"
            except Exception:
                error = UnexpectedPayloadError(
                    "No errors found in payload",
                    response=response,
                )
                log_exception(error)
                raise error
            error = AuthenticationFailure(
                error_msg,
                response=response,
            )
            log_exception(error)
            raise error

        # JSESSIONID Cookie is automatically set by httpx.client for future requests
        if not self.client.cookies.get("JSESSIONID"):
            error = AuthenticationFailure(
                "No JSESSIONID session cookie found in authentication response",
                response=response,
            )
            log_exception(error)
            raise error

        # Get XSRF Token
        response = self.request(
            "GET",
            "/client/token",
            auth=None,
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
        )

        # XSRF tokens for vManage are always 100 hex digits
        if re.match(r"[0-9A-Z]{100}", response.text):
            self.xsrftoken = response.text
            self.headers["X-XSRF-TOKEN"] = self.xsrftoken
        else:
            error = AuthenticationFailure(
                "Unable to obtain XSRF token",
                response=response,
            )
            log_exception(error)
            raise error

        return response

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return self.xsrftoken is not None

    def _after_auth(self, **kwargs) -> None:
        """
        Unused for vManage
        """
        pass

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

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
        !!! failure "HTTP PATCH is not supported by Cisco SD-WAN vManage API"

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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

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
        page_size: int = 500,
    ) -> list:
        """
        Retrieves all pages of data from a `GET` endpoint.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

        page_size : int, default=500
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `data` key in the Cisco SD-WAN vManage API JSON responses.

        Raises
        ------
        UnexpectedPayloadError
            When a repsonse doesn't match any of the pagination methods
            (scroll based or limit/offset based)
            or the fallback root list or `data` key can't be found.
        """

        logger.debug(f"Retrieving all pages from {path}")

        if path.endswith("/page"):
            # Queries on a "stats database" uses scollId flavor pagination
            result = self.get_all_statistics(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
                page_size=page_size,
            )

        elif path.startswith("/template"):
            # Queries on a "configuration database" uses offset/limit flavor pagiantion
            result = self.get_all_configuration(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
                page_size=page_size,
            )

        else:
            only_page = self.get(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
            )
            page_data = only_page.json()
            if isinstance(page_data, list):
                result = page_data
            elif "data" in page_data:
                result = page_data["data"]
            else:
                error = UnexpectedPayloadError(
                    f"Unable to find appropriate items in JSON payload with keys: {list(page_data.keys())}",
                    response=only_page,
                )
                log_exception(error)
                raise error

        return result

    def get_all_statistics(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 10000,
    ):
        """
        Retrieves all pages of data from a `GET` endpoint related to the statistics database.
        Pagination is based on scrollId.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

        page_size : int, default=10000
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `data` key in the Cisco SD-WAN vManage API JSON responses.
        """
        if isinstance(params, dict):
            params = params.copy()
        else:
            params = {}

        params["count"] = page_size

        result = []
        more_pages = True

        while more_pages:
            page = self.get(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
            )

            page_data = page.json()
            result += page_data.get("data", [])
            more_pages = page_data["pageInfo"]["hasMoreData"]
            params["scrollId"] = page_data.get("pageInfo", {}).get("scrollId")

        return result

    def get_all_configuration(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 50,
    ):
        """
        Retrieves all pages of data from a `GET` endpoint related to the configuration database.
        Pagination is based on limit/offset.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

        page_size : int, default=500
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `data` key in the Cisco SD-WAN vManage API JSON responses.
        """
        result = []
        offset = 1

        while True:
            page = self.get_page_configuration(
                path,
                params=params,
                path_params=path_params,
                offset=offset,
                limit=page_size,
                headers=headers,
                timeout=timeout,
            )
            offset += page_size
            if "data" not in page.json():
                error = UnexpectedPayloadError(
                    "No data found in payload",
                    response=page,
                )
                log_exception(error)
                raise error

            page_reponse = page.json()["data"]
            result += page_reponse

            if len(page_reponse) < page_size:
                logger.trace("Exiting pagination loop.")
                break

        logger.debug(f"Received {len(result)} items from {path}")

        return result

    def get_page_configuration(
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
        Retrieves a specific page of data from a `GET` endpoint related to the configuration database.
        Uses offset/limit based pagination.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        offset : int
            Index of first items of the page. First item is offset 1.

        limit : int
            The number of items to retrieve per page.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/vmanage/#wingpy.cisco.vManage.CiscoVmanage.timeout) for a single request.

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

        page_reponse = rsp.json()["data"]
        if len(page_reponse) > 0:
            logger.debug(f"Successfully retrieved page {page} from {path}.")
        else:
            logger.debug(f"Page {page} returned no items.")

        return rsp
