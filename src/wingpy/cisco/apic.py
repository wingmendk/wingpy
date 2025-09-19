# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import copy
import json
import math
import os
import re
from ssl import SSLContext
from urllib.parse import urlparse

import httpx
from lxml import etree
from packaging.version import Version

from wingpy.base import HttpResponsePattern, RestApiBaseClass
from wingpy.exceptions import (
    AuthenticationFailure,
    InvalidResponseError,
    UnsupportedMethodError,
)
from wingpy.logger import log_exception, logger


class CiscoAPIC(RestApiBaseClass):
    """
    Interact with the Cisco Application Policy Infrastructure Controller (APIC) API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_APIC_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_APIC_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_APIC_PASSWORD`.

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
    from wingpy import CiscoAPIC
    apic = CiscoAPIC(
        base_url="https://apic.example.com",
        username="admin",
        password="password",
        verify=False,
    )
    apic.get_all("/api/class/fvTenant.json")
    ```
    """

    RETRY_RESPONSES = [
        HttpResponsePattern(
            status_codes=[503],
            methods=["GET", "POST", "DELETE"],
            content_patterns=[
                re.compile(
                    r"<!DOCTYPE html>\n<html>\n<head>\n<title>Error</title>\n<style>\n    body {\n        width: 35em;\n        margin: 0 auto;\n        font-family: Tahoma, Verdana, Arial, sans-serif;\n    }\n</style>\n</head>\n<body>\n<h1>An error occurred\.</h1>\n<p>Sorry, the page you are looking for is currently unavailable\.<br/>\nPlease try again later\.</p>\n<p>If you are the system administrator of this resource then you should check\nthe error log for details\.</p>\n<p><em>Faithfully yours, nginx\.</em></p>\n</body>\n</html>\n"
                )
            ],
        ),
    ]
    """
    Cisco APIC has not implemented HTTP status code 429 for rate limiting.
    Instead it returns an NGINX default error page with HTTP status code 503.
    """

    MAX_CONNECTIONS = 20
    """
    The maximum number of concurrent connections opened to the APIC.
    
    1 connection will be used for general synchronous requests.
    
    19 connections will be used for parallel asynchronous requests.
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
        self.apic_url: str | None = base_url or os.getenv("WINGPY_APIC_BASE_URL")
        """
        The base URL for the APIC API.

        If not provided, it will be read from the environment variable `WINGPY_APIC_BASE_URL`.
        
        Examples
        --------
        - https://apic.example.com
        - https://192.0.2.1:443
        """

        self.username: str | None = username or os.getenv("WINGPY_APIC_USERNAME")
        """
        The username for authentication to the APIC API.

        If not provided, it will be read from the environment variable `WINGPY_APIC_USERNAME`.
        """

        self.password: str | None = password or os.getenv("WINGPY_APIC_PASSWORD")
        """
        The password for authentication to the APIC API.

        If not provided, it will be read from the environment variable `WINGPY_APIC_PASSWORD`.
        """

        if not self.apic_url or not self.username or not self.password:
            raise ValueError(
                "APIC base_url, username and password must be provided either as arguments or environment variables"
            )

        super().__init__(
            base_url=self.apic_url,
            auth_lifetime=600,
            auth_refresh_percentage=0.9,
            verify=verify,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=timeout,
            retries=retries,
        )

        self.version: Version | None = None
        """
        The version of the APIC API.
        """

        self._token: str | None = None
        """
        The current token for the APIC API.
        """

    def _authenticate(self) -> httpx.Response:
        """
        Retrieves and stores an `APIC-Cookie` cookie header by authenticating
        with the APIC API using the provided username and password.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`CiscoAPIC.authenticate()`](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.authenticate)

        Returns
        -------
        httpx.Response
            The response object from the authentication request.
        """

        parsed_url = urlparse(self.base_url)

        logger.info(
            f"Authenticating with APIC {parsed_url.netloc} as user: {self.username}"
        )

        auth_payload = {
            "aaaUser": {"attributes": {"name": self.username, "pwd": self.password}}
        }

        # Authenticate with APIC auth payload to obtain an access token

        response = self.request(
            "POST",
            "/api/aaaLogin.json",
            data=auth_payload,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            is_auth_endpoint=True,
            auth=None,
        )

        if response.status_code != 200:  # pragma: no cover
            error = AuthenticationFailure(
                "Authentication failed",
                response=response,
            )
            log_exception(error)
            raise error

        try:
            response_data = response.json()
        except json.JSONDecodeError:  # pragma: no cover
            error = AuthenticationFailure(
                "Authentication response is not in JSON format", response=response
            )
            log_exception(error)
            raise error

        try:
            self._token = response_data["imdata"][0]["aaaLogin"]["attributes"]["token"]
        except (KeyError, IndexError):  # pragma: no cover
            error = AuthenticationFailure(
                "Failed to retrieve authentication token from response.",
                response=response,
            )
            log_exception(error)
            raise error

        self.headers["Cookie"] = f"APIC-Cookie={self._token}"

        return response

    def _after_auth(self, *, auth_response):
        """
        Handle meta data retrieval after authentication.
        """

        auth_rsp_payload = auth_response.json()
        refresh_timeout = auth_rsp_payload["imdata"][0]["aaaLogin"]["attributes"][
            "refreshTimeoutSeconds"
        ]
        self.auth_lifetime = int(refresh_timeout)

        response = self.request(
            "GET",
            "/api/node/mo/uni/fabric/comm-default/https.json",
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            is_auth_endpoint=True,
            auth=None,
        )

        if response.status_code == 200:
            https_throttle = response.json()["imdata"][0]["commHttps"]["attributes"]

            if https_throttle["globalThrottleSt"] == "enabled":
                if https_throttle["globalThrottleUnit"] == "r/m":  # pragma: noqa
                    self.rate_limit_period = 60
                elif https_throttle["globalThrottleUnit"] == "r/s":
                    self.rate_limit_period = 1

                self.rate_limit_max_requests = int(https_throttle["globalThrottleRate"])
                logger.info(
                    f"Rate limit for APIC is enabled with {self.rate_limit_max_requests} requests per {self.rate_limit_period} seconds"
                )
        else:
            logger.info("Unable to detect throttle rate for APIC")

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return self._token is not None

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
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

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
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        if isinstance(data, (dict, list)) and not path.endswith(".json"):
            raise ValueError("JSON data must be sent to an endpoint with .json suffix")
        elif isinstance(data, etree._Element) and not path.endswith(".xml"):
            raise ValueError("XML data must be sent to an endpoint with .xml suffix")

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

    def put(self, *args, **kwargs) -> None:  # type: ignore
        """
        !!! failure "HTTP PUT is not supported by APIC"

        Raises
        ------
        UnsupportedMethodError
        """
        error = UnsupportedMethodError(client=self, method="PUT")
        log_exception(error)
        raise error

    def patch(self, *args, **kwargs) -> None:  # type: ignore
        """
        !!! failure "HTTP PATCH is not supported by APIC"

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
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        Returns
        -------
        httpx.Response
            The [`httpx.Response`](https://www.python-httpx.org/api/#response) object from the request.
        """

        response = self.request(
            "DELETE",
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

    def get_all(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 2000,
    ) -> list[dict] | etree._Element:
        """
        Retrieves all pages of data from an API endpoint path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        page_size : int | None, default=2000
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of dictionaries represented in the JSON responses.

        etree._Element
            A merged `lxml` element of subelements represented in the XML responses.
        """

        if path.lower().endswith(".json"):
            result = self.get_all_json(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
                page_size=page_size,
            )
        elif path.lower().endswith(".xml"):
            result = self.get_all_xml(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
                page_size=page_size,
            )
        else:
            raise ValueError(
                "APIC API path must end with either .json or .xml to determine the response format"
            )
        logger.debug(f"Received {len(result)} items from {path}")
        return result

    def get_all_json(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 2000,
    ) -> list[dict]:
        """
        Retrieves all pages of data from a JSON API endpoint path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        page_size : int | None, default=2000
            The number of items to retrieve per page.

        Returns
        -------
        list[dict]
            A concatenated list of dictionaries represented in the JSON responses.
        """

        logger.debug(f"Retrieving all pages from {path}")

        first_page = self.get_page_json(
            path,
            params=params,
            path_params=path_params,
            page=0,
            page_size=page_size,
            headers=headers,
            timeout=timeout,
        )

        json_response_data = first_page.json()

        # Initialize the result using the first page
        result: list = json_response_data["imdata"]

        # Find the number of pages to retrieve
        total_count = int(json_response_data["totalCount"])
        total_pages = math.ceil(total_count / page_size)

        # Prepare the pages to be retrieved in parallel
        for page in range(1, total_pages + 1):
            self.tasks.schedule(
                self.get_page_json,
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
            result += page_response.json()["imdata"]

        logger.debug(f"Received {len(result)} items from {path}")

        return result

    def get_all_xml(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        page_size: int = 2000,
    ) -> etree._Element:
        """
        Retrieves all pages of data from an XML API endpoint path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        page_size : int | None, default=2000
            The number of items to retrieve per page.

        Returns
        -------
        etree._Element
            A merged `lxml` element of subelements represented in the XML responses.
        """

        logger.debug(f"Retrieving all pages from {path}")

        first_page = self.get_page_xml(
            path,
            params=params,
            path_params=path_params,
            page=0,
            page_size=page_size,
            headers=headers,
            timeout=timeout,
        )

        first_xml_response_element = etree.fromstring(first_page.content)  # type: ignore

        # Initialize the result using the first page
        result_elem: etree._Element = etree.Element("imdata")  # type: ignore
        for child in first_xml_response_element:
            result_elem.append(copy.deepcopy(child))

        # Find the number of pages to retrieve
        total_count = int(first_xml_response_element.get("totalCount"))
        total_pages = math.ceil(total_count / page_size)

        # Prepare the pages to be retrieved in parallel
        for page in range(1, total_pages + 1):
            self.tasks.schedule(
                self.get_page_xml,
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
            page_response_data = etree.fromstring(page_response.content)  # type: ignore
            for child in page_response_data.getchildren():
                result_elem.append(copy.deepcopy(child))

        logger.debug(f"Received {len(result_elem)} items from {path}")

        return result_elem

    def get_page_json(
        self,
        path: str,
        *,
        page: int,
        page_size: int,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
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
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        Returns
        -------
        httx.Response
            The response object from the request.
        """

        merged_params = {}
        if isinstance(params, dict):
            merged_params.update(params)

        merged_params["page-size"] = page_size
        merged_params["page"] = page

        json_response = self.get(
            path,
            params=merged_params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        json_response_data = json_response.json()

        if "totalCount" not in json_response_data.keys():  # pragma: no cover
            err = InvalidResponseError(
                f'Paginated response payload is expected to have an "totalCount" key. Available keys: {json_response_data.keys()}',
                response=json_response,
            )
            log_exception(err)
            raise err

        if "imdata" not in json_response_data.keys():  # pragma: no cover
            err = InvalidResponseError(
                f'Paginated response payload is expected to have an "imdata" key. Available keys: {json_response_data.keys()}',
                response=json_response,
            )
            log_exception(err)
            raise err

        total_count = int(json_response_data.get("totalCount"))

        total_pages = math.ceil(total_count / page_size)

        logger.debug(f"Successfully retrieved page {page} of {total_pages} from {path}")

        return json_response

    def get_page_xml(
        self,
        path: str,
        *,
        page: int,
        page_size: int,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        """
        Retrieves a specific page of data from an XML path.

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
            Replace placeholders like `{rn}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/apic/#wingpy.cisco.apic.CiscoAPIC.timeout) for a single request.

        Returns
        -------
        httx.Response
            The response object from the request.
        """

        merged_params = {}
        if isinstance(params, dict):
            merged_params.update(params)

        merged_params["page-size"] = page_size
        merged_params["page"] = page

        xml_response = self.get(
            path,
            params=merged_params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        xml_response_data = etree.fromstring(xml_response.content)  # type: ignore

        if "totalCount" not in xml_response_data.keys():  # pragma: no cover
            # Invalid response payload
            raise KeyError(
                f'Paginated response payload is expected to have an "totalCount" attribute. Available keys: {xml_response_data.keys()}'
            )

        if len(xml_response_data.items()) < 1:  # pragma: no cover
            error = InvalidResponseError(
                "Paginated response payload is expected to have child elements. No children found.",
                response=xml_response,
            )
            log_exception(error)
            raise error

        total_count = int(xml_response_data.get("totalCount"))

        total_pages = math.ceil(total_count / page_size)

        logger.debug(f"Successfully retrieved page {page} of {total_pages} from {path}")

        return xml_response
