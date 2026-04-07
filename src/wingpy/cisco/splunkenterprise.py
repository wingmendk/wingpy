# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import os
import re
from ssl import SSLContext
from time import sleep
from urllib.parse import urlencode, urljoin

import httpx
from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import UnsupportedMethodError
from wingpy.logger import logger
from wingpy.response import XMLResponseMapping, ResponseMapping, ResponseSequence


class SplunkEnterprise(RestApiBaseClass):
    """
    Interact with the Splunk Enterprise API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_SPLUNK_ENTERPRISE_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_SPLUNK_ENTERPRISE_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_SPLUNK_ENTERPRISE_PASSWORD`.

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
    from wingpy import SplunkEnterprise
    splunk = SplunkEnterprise(
        base_url="",
        username="example_username",
        password="example_password",
    )
    splunk.get("/")
    ```
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Splunk Enterprise.
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to the Splunk Enterprise.
    
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
        self.splunk_url = base_url or os.getenv("WINGPY_SPLUNK_ENTERPRISE_BASE_URL")
        """
        The base URL for the Splunk Enterprise API.

        If not provided, it will be read from the environment variable `WINGPY_SPLUNK_ENTERPRISE_BASE_URL`.
        """

        self.username = username or os.getenv("WINGPY_SPLUNK_ENTERPRISE_USERNAME")
        """
        The username for authentication.
        If not provided, it will be read from the environment variable `WINGPY_SPLUNK_ENTERPRISE_USERNAME`.
        """

        self.password = password or os.getenv("WINGPY_SPLUNK_ENTERPRISE_PASSWORD")
        """
        The password for authentication.
        If not provided, it will be read from the environment variable `WINGPY_SPLUNK_ENTERPRISE_PASSWORD`.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided either as argument or environment variable"
            )
        self.auth = httpx.BasicAuth(username=self.username, password=self.password)
        """
        The authentication object for the Splunk Enterprise API.
        """

        if not self.splunk_url:
            raise ValueError(
                "Splunk Enterprise base_url must be provided either as argument or environment variable"
            )
        elif not self.splunk_url.endswith("/services"):
            raise ValueError("Splunk Enterprise base_url must end with /services")

        self.version: Version = Version("0.0")
        """
        The version of the Splunk Enterprise API.
        """

        super().__init__(
            base_url=self.splunk_url,
            verify=verify,
            timeout=timeout,
            retries=retries,
        )

        self.auth = httpx.BasicAuth(self.username, self.password)
        """
        The authentication credentials for the Splunk Enterprise API.
        """

    def _authenticate(self) -> None:
        """
        Retrieves and stores an `X-auth-token` cookie header by authenticating
        with the Splunk Enterprise API using the provided username and password.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`SplunkEnterprise.authenticate()`](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.authenticate)

        Returns
        -------
        None
        """

        pass

    @property
    def is_authenticated(self):
        """
        Check if the client is authenticated.
        """
        return self.version is not None

    def _after_auth(self, **kwargs) -> None:
        """
        Handle meta data retrieval after authentication.
        """

        response = self.request(
            "GET",
            "/server/info",
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            auth=self.auth,
        )
        try:
            generators = response.xpath(
                "/a:feed/a:generator", namespaces={"a": "http://www.w3.org/2005/Atom"}
            )
            version = generators[0].get("version", "0.0")
            self.version = Version(version)
            logger.info(f"Splunk Enterprise version: {self.version} detected")
        except Exception:
            logger.warning("Unable to detect Splunk Enterprise version")

    def get(
        self,
        path: str,
        *,
        params: dict | None = None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> XMLResponseMapping | ResponseMapping | ResponseSequence:
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

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.timeout) for a single request.

        Returns
        -------
        XMLResponseMapping | ResponseMapping | ResponseSequence
            The [`XMLResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.XMLResponseMapping), [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence) object from the request.
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
            auth=self.auth,
        )

        return response

    def post(
        self,
        path: str,
        *,
        data: dict | None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> XMLResponseMapping | ResponseMapping | ResponseSequence:
        """
        Send an HTTP `POST` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : dict | None, default=None
            Request parameters as a Python dictionary object. Will be encoded for `application/x-www-form-urlencoded` in the request body.

        path_params : dict | None, default=None
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.timeout) for a single request.

        Returns
        -------
        XMLResponseMapping | ResponseMapping | ResponseSequence
            The [`XMLResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.XMLResponseMapping), [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence) object from the request.
        """

        payload = urlencode(data)

        if isinstance(headers, dict):
            headers = headers.copy()
        else:
            headers = {}

        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        response = self.request(
            "POST",
            path,
            data=payload,
            params=None,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
            is_auth_endpoint=False,
            auth=self.auth,
        )
        return response

    def put(self) -> None:  # ignore: type
        """
        !!! failure "HTTP PUT is not supported by Splunk Enterprise API"

        Raises
        ------
        UnsupportedMethodError
        """
        raise UnsupportedMethodError(
            "Splunk Enterprise API does not support PUT requests"
        )

    def patch(self) -> None:  # ignore: type
        """
        !!! failure "HTTP PATCH is not supported by Splunk Enterprise API"

        Raises
        ------
        UnsupportedMethodError
        """
        raise UnsupportedMethodError(
            "Splunk Enterprise API does not support PATCH requests"
        )

    def delete(
        self,
        path: str,
        *,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> XMLResponseMapping | ResponseMapping | ResponseSequence:
        """
        Send an HTTP `DELETE` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        path_params : dict | None, default=None
            Replace placeholders like `{siteId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.timeout) for a single request.

        Returns
        -------
        XMLResponseMapping | ResponseMapping | ResponseSequence
            The [`XMLResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.XMLResponseMapping), [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence) object from the request.
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
    ) -> list:
        """
        Retrieves all entries from a `GET` endpoint by setting the `count` parameter to
        `0` and handling the asynchronous response if results are not immediately available.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/splunk/#wingpy.splunkenterprise.SplunkEnterprise.timeout) for a single request.

        Returns
        -------
        list[dict]
            A concatenated list of returned dictionaries from all pages.

            Similar to the `response` key in the Splunk Enterprise API JSON responses.
        """

        if params is None:
            params = {}
        else:
            params = params.copy()

        params["count"] = 0

        response = self.get(
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        # If response is empty but contains a link header, we are still waiting for results to be generated.
        if response.status_code == 204 and "rel=info" in response.headers.get(
            "link", ""
        ):
            # Construct the info path and query until results are ready
            match = re.search(
                r"<(?P<path>\.\./[^>]+)>;\s*rel=info", response.headers.get("link", "")
            )
            if not match:
                return response
            logger.debug("Entries not ready, checking info link for status updates")
            info_link = match.group("path")
            info_path = urljoin(path, info_link)
            while True:
                info_response = self.get(info_path, timeout=timeout)
                if info_response.status_code == 200:
                    # Example response:
                    # <?xml version="1.0" encoding="UTF-8"?>
                    # <entry xmlns="http://www.w3.org/2005/Atom">
                    #   <content type="text/xml">
                    #     <s:dict>
                    #       <s:key name="dispatchState">PARSING</s:key>

                    # Root element is in the http://www.w3.org/2005/Atom namespace and
                    # the dispatchState dict and key is in the
                    # http://dev.splunk.com/ns/rest namespace, so we need to use the
                    # corresponding namespaces and prefixes in the XPath query.

                    dispatch_states = info_response.xpath(
                        "/a:entry/a:content/s:dict/s:key[@name='dispatchState']/text()",
                        namespaces={
                            "a": "http://www.w3.org/2005/Atom",
                            "s": "http://dev.splunk.com/ns/rest",
                        },
                    )
                    # If we cannot find the dispatch state, we can't determine if this is still processing or if it is done,
                    # so we return the original response and let the user handle it.
                    if not dispatch_states:
                        return response
                    dispatch_state = dispatch_states[0]
                    logger.debug(f"Result status: {dispatch_state}")
                    if dispatch_state not in ("PARSING", "RUNNING", "FINALIZING"):
                        break

                    sleep(self.throttler.backoff_initial)

            # Once the results are ready, retry the original request to get the results
            response = self.get(
                path,
                params=params,
                path_params=path_params,
                headers=headers,
                timeout=timeout,
            )

        if isinstance(response, XMLResponseMapping):
            if response._root.tag.lower() == "{http://www.w3.org/2005/atom}feed":
                return response.xpath(
                    "/a:feed/a:entry", namespaces={"a": "http://www.w3.org/2005/Atom"}
                )
            elif response._root.tag.lower() == "results":
                return response.xpath("/results/result")
            else:
                raise ValueError("Unexpected XML response format for get-all endpoint")
        elif isinstance(response, ResponseSequence):
            return list(response)
        elif isinstance(response, ResponseMapping):
            if "results" in response:
                return response["results"]
            elif "entry" in response:
                return response["entry"]
            elif "columns" in response:
                return response["columns"]
            elif "rows" in response:
                return response["rows"]
            else:
                raise ValueError("Unexpected JSON response format for get-all endpoint")

        return response
