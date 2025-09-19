# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import math
import os
from ssl import SSLContext

import httpx
from lxml import etree
from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import InvalidEndpointError
from wingpy.logger import log_exception, logger


class CiscoISE(RestApiBaseClass):
    """
    Interact with the Cisco Identity Service Engine (ISE) API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_ISE_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_ISE_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_ISE_PASSWORD`.

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
    from wingpy import CiscoISE
    ise = CiscoISE(
        base_url="https://ise.example.com",
        username="admin",
        password="password",
        verify=False,
    )
    ise.get_all("/api/v1/endpoint")
    ```
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Cisco ISE.
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to the ISE.
    
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
        self.ise_url: str | None = base_url or os.getenv("WINGPY_ISE_BASE_URL")
        """
        The base URL for the ISE API.

        If not provided, it will be read from the environment variable `WINGPY_ISE_BASE_URL`.
        
        Examples
        --------
        - https://ise.example.com
        - https://192.0.2.1:443
        """

        self.username: str | None = username or os.getenv("WINGPY_ISE_USERNAME")
        """
        The username for authentication to the ISE API.

        If not provided, it will be read from the environment variable `WINGPY_ISE_USERNAME`.
        """

        self.password: str | None = password or os.getenv("WINGPY_ISE_PASSWORD")
        """
        The password for authentication to the ISE API.

        If not provided, it will be read from the environment variable `WINGPY_ISE_PASSWORD`.
        """

        if not self.ise_url or not self.username or not self.password:
            raise ValueError(
                "ISE base_url, username and password must be provided either as arguments or environment variables"
            )

        super().__init__(
            base_url=self.ise_url,
            auth_lifetime=0,
            auth_refresh_percentage=1,
            verify=verify,
            timeout=timeout,
            retries=retries,
        )

        self.auth = httpx.BasicAuth(self.username, self.password)
        """
        The authentication credentials for the ISE API.
        """

        self.version: Version | None = None
        """
        The version of the ISE API.
        """

    def _authenticate(self) -> None:  # type: ignore
        """
        No dedicated authentication is available for ISE.
        """
        pass

    def _after_auth(self, **kwargs) -> None:
        """
        Handle meta data retrieval after authentication.
        """

        xml_response = self.request(
            "GET",
            "/admin/API/mnt/Version",
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            auth=self.auth,
        )
        if xml_response.status_code == 200:
            xml_response_data = etree.fromstring(xml_response.content)  # type: ignore
            self.version = Version(xml_response_data.xpath("//version")[0].text)
            logger.info(f"ISE version: {self.version} detected")
        else:
            logger.info("Unable to detect ISE version")

    @property
    def is_authenticated(self) -> bool:
        """
        Check if the client is authenticated.
        """
        return self.version is not None

    def _build_mimetype_headers(self, *, path: str) -> dict:
        """
        Return appropricate Content-Type and Accept headers
        based on API endpoint path.
        """
        if self.is_xml(path):
            return {
                "Content-Type": "application/xml",
                "Accept": "application/xml",
            }
        else:
            return {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

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
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        merged_headers = self.headers.copy()
        merged_headers.update(self._build_mimetype_headers(path=path))
        if isinstance(headers, dict):
            merged_headers.update(headers)

        response = self.request(
            "GET",
            path,
            data=None,
            params=params,
            path_params=path_params,
            headers=merged_headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=self.auth,
        )
        return response

    def post(
        self,
        path: str,
        *,
        data: str | dict | list | etree._Element | None,
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

        data : str | dict | list | etree._Element | None
            Request payload as JSON string, Python list/dict object or XML Element.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        merged_headers = self.headers.copy()
        merged_headers.update(self._build_mimetype_headers(path=path))
        if isinstance(headers, dict):
            merged_headers.update(headers)

        response = self.request(
            "POST",
            path,
            data=data,
            params=None,
            path_params=path_params,
            headers=merged_headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=self.auth,
        )

        return response

    def put(
        self,
        path: str,
        *,
        data: str | dict | list | etree._Element | None,
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

        data : str | dict | list | etree._Element | None
            Request payload as JSON string, Python list/dict object or XML Element.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        merged_headers = self.headers.copy()
        merged_headers.update(self._build_mimetype_headers(path=path))
        if isinstance(headers, dict):
            merged_headers.update(headers)

        response = self.request(
            "PUT",
            path,
            data=data,
            params=None,
            path_params=path_params,
            headers=merged_headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=self.auth,
        )

        return response

    def patch(
        self,
        path: str,
        *,
        data: str | dict | list | etree._Element | None,
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

        data : str | dict | list | etree._Element | None
            Request payload as JSON string, Python list/dict object or XML Element.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        merged_headers = self.headers.copy()
        merged_headers.update(self._build_mimetype_headers(path=path))
        if isinstance(headers, dict):
            merged_headers.update(headers)

        response = self.request(
            "PATCH",
            path,
            data=data,
            params=None,
            path_params=path_params,
            headers=merged_headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=self.auth,
        )

        return response

    def delete(
        self,
        path: str,
        *,
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

        data : str | dict | list | etree._Element | None
            Request payload as JSON string, Python list/dict object or XML Element.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        merged_headers = self.headers.copy()
        merged_headers.update(self._build_mimetype_headers(path=path))
        if isinstance(headers, dict):
            merged_headers.update(headers)

        response = self.request(
            "DELETE",
            path,
            data=data,
            params=None,
            path_params=path_params,
            headers=merged_headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=self.auth,
        )

        return response

    def is_ers(self, path: str) -> bool:
        """
        Check if the given path is an ERS endpoint.

        Parameters
        ----------
        path
            The API endpoint path to check.

        Returns
        -------
        bool
            True if the path is an ERS endpoint, False otherwise.
        """
        path_is_ers_endpoint = "/ers/config" in f"{self.base_url}{path}"
        logger.trace(f"Path {path} is ERS endpoint: {path_is_ers_endpoint}")
        return path_is_ers_endpoint

    def is_xml(self, path: str) -> bool:
        """
        Check if the given path is an XML endpoint.

        Parameters
        ----------
        path
            The API endpoint path to check.

        Returns
        -------
        bool
            True if the path is an XML endpoint, False otherwise.
        """
        path_is_xml_endpoint = (
            "/admin/API/NetworkAccessConfig/ERS" in f"{self.base_url}{path}"
            or "/admin/API/mnt/" in f"{self.base_url}{path}"
        )
        logger.trace(f"Path {path} is XML endpoint: {path_is_xml_endpoint}")
        return path_is_xml_endpoint

    def get_all(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 100,
    ) -> list[dict]:
        """
        Retrieves all pages of data from an API endpoint path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        page_size : int | None, default=100
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of dictionaries represented in the JSON responses.
        """

        if self.is_ers(path):
            return self.get_all_ers(
                path,
                params=params,
                path_params=path_params,
                page_size=page_size,
                headers=headers,
                timeout=timeout,
            )
        elif self.is_xml(path):
            error = InvalidEndpointError(client=self, endpoint_path=path)
            log_exception(error)
            raise error
        else:
            return self.get_all_openapi(
                path,
                params=params,
                path_params=path_params,
                page_size=page_size,
                headers=headers,
                timeout=timeout,
            )

    def get_all_openapi(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 100,
    ) -> list[dict]:
        """
        Retrieves all pages of data from an OpenAPI endpoint path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        page_size : int | None, default=100
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of dictionaries, similar to the root list in the JSON responses.


        Raises
        ------
        InvalidEndpointError
            If the specified path is not a valid OpenAPI "Get all" endpoint.
        """

        logger.debug(f"Retrieving all pages from OpenAPI {path}")

        page = 1
        result: list = []

        while True:
            page_response = self.get_page(
                path,
                params=params,
                path_params=path_params,
                page=page,
                page_size=page_size,
                headers=headers,
                timeout=timeout,
            )

            if page_response.status_code == 400:
                # Empty page means we have reached the end
                break

            json_response_data = page_response.json()
            if not isinstance(json_response_data, list):
                error = InvalidEndpointError(
                    f'{path} is not an OpenAPI "Get all" endpoint',
                    client=self,
                    endpoint_path=path,
                )
                log_exception(error)
                raise error

            result += json_response_data
            if len(json_response_data) < page_size:
                # No more pages available
                break
            else:
                page += 1

        logger.debug(f"Received {len(result)} items from {path}")

        return result

    def get_all_ers(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 100,
    ) -> list[dict]:
        """
        Retrieves all pages of data from an ERS endpoint path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        page_size : int | None, default=100
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of dictionaries, similar to the `resources` key in the JSON responses.
        """

        logger.debug(f"Retrieving all pages from ERS {path}")

        first_page = self.get_page(
            path,
            params=params,
            path_params=path_params,
            page=1,
            page_size=page_size,
            headers=headers,
            timeout=timeout,
        )

        json_response_data = first_page.json()

        if "SearchResult" not in json_response_data.keys():
            error = InvalidEndpointError(
                f'{path} is not an ERS "Get-All" endpoint',
                client=self,
                endpoint_path=path,
            )
            log_exception(error)
            raise error

        result: list = json_response_data["SearchResult"]["resources"]

        total_count = int(json_response_data["SearchResult"]["total"])

        total_pages = math.ceil(total_count / page_size)

        logger.trace(
            f"Paging with {range(page_size, total_count, page_size) = } = {list(range(page_size, total_count, page_size))}"
        )

        # Prepare the pages to be retrieved in parallel
        for page in range(2, total_pages + 1):
            self.tasks.schedule(
                self.get_page,
                path,
                params=params,
                path_params=path_params,
                page=page,
                page_size=page_size,
                headers=headers,
                timeout=timeout,
            )

        page_responses = self.tasks.run()

        for page_response in page_responses.values():
            result += page_response.json()["SearchResult"]["resources"]

        logger.debug(f"Received {len(result)} items from {path}")

        return result

    def get_page(
        self,
        path: str,
        *,
        page: int,
        page_size: int,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None,
    ) -> httpx.Response:
        """
        Retrieves a specific page of data from a JSON path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        page : int
            Page number to retrive.

        page_size : int
            The number of items to retrieve per page.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{policyId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.ise.CiscoISE.timeout) for a single request.

        Returns
        -------
        httx.Response
            The response object from the request.
        """

        merged_params = {}
        if isinstance(params, dict):
            merged_params.update(params)

        merged_params["size"] = page_size
        merged_params["page"] = page

        response = self.get(
            path,
            params=merged_params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        if response.status_code < 300:
            logger.debug(f"Retrieved page {page} from {path}")

        return response
