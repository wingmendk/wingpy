# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import base64
import json
import os
from ssl import SSLContext

import arrow
import httpx
from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import AuthenticationFailure, UnsupportedMethodError
from wingpy.logger import log_exception, logger


class CiscoModelingLabs(RestApiBaseClass):
    """
    Interact with the Cisco Modeling Labs API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`. Must end with `/api/v0`.

        Overrides the environment variable `WINGPY_CML_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_CML_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_CML_PASSWORD`.

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
    from wingpy import CiscoModelingLabs
    cml = CiscoModelingLabs(
        base_url="https://cml.example.com/api/v0",
        username="example_username",
        password="example_password",
    )
    cml.get("/")
    ```

    Raises
    ------
    ValueError
        When base_url, username or password is missing

    ValueError
        When base_url does not end with `/api/v0`
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Cisco Modeling Labs.
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to the Cisco Modeling Labs.
    
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
        self.cml_url = base_url or os.getenv("WINGPY_CML_BASE_URL")
        """
        The base URL for the Cisco Modeling Labs API.

        If not provided, it will be read from the environment variable `WINGPY_CML_BASE_URL`.
        """

        self.username = username or os.getenv("WINGPY_CML_USERNAME")
        """
        The username for authentication.
        If not provided, it will be read from the environment variable `WINGPY_CML_USERNAME`.
        """

        self.password = password or os.getenv("WINGPY_CML_PASSWORD")
        """
        The password for authentication.
        If not provided, it will be read from the environment variable `WINGPY_CML_PASSWORD`.
        """

        self.token = None
        """
        The authentication token for the Cisco Modeling Labs API.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided either as argument or environment variable"
            )

        if not self.cml_url:
            raise ValueError(
                "Cisco Modeling Labs base_url must be provided either as argument or environment variable"
            )
        elif not self.cml_url.endswith("/api/v0"):
            raise ValueError("Cisco Modeling Labs base_url must end with /api/v0")

        self.version: Version = Version("0.0")
        """
        The version of the Cisco Modeling Labs API.
        """

        super().__init__(
            base_url=self.cml_url,
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
        Retrieves and stores a bearer token by authenticating with the
        Cisco Modeling Labs API using the provided username and password as JSON payload.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`CiscoModelingLabs.authenticate()`](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.authenticate)

        Returns
        -------
        httpx.Response
            The response object from the authentication request.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided for authentication"
            )

        data = {
            "username": self.username,
            "password": self.password,
        }

        response = self.request(
            "POST",
            "/authenticate",
            auth=None,
            is_auth_endpoint=True,
            data=data,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
        )

        if response.status_code != 200:
            error = AuthenticationFailure(
                response.json().get("description"),
                response=response,
            )
            log_exception(error)
            raise error

        self.token = response.json()
        self.headers["Authorization"] = f"Bearer {self.token}"

        # Split JWT token to extract payload with expiration time
        jwt = self.token.split(".")
        jwt_payload_padded = jwt[1] + "=" * divmod(len(jwt[1]), 4)[1]

        # Decode payload and calculate lifetime
        jwt_payload = json.loads(base64.urlsafe_b64decode(jwt_payload_padded))
        self.auth_lifetime = int(jwt_payload["exp"] - arrow.utcnow().timestamp())

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
            raise AuthenticationFailure("Authentication required before use")

        response = self.request(
            "GET",
            "/system_information",
            is_auth_endpoint=True,
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            auth=None,
        )
        if response.status_code == 200:
            version = response.json().get("version", "0.0")
            self.version = Version(version)
            logger.info(f"Cisco Modeling Labs version: {self.version} detected")
        else:
            logger.info("Unable to detect Cisco Modeling Labs version")

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
            Replace placeholders like `{lab_id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.timeout) for a single request.

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
            Replace placeholders like `{lab_id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cml.CiscoModelingLabs.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cml.CiscoModelingLabs.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cml.CiscoModelingLabs.timeout) for a single request.

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
        data: str | dict | list | None = None,
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

        data : str | dict | list | None, default=None
            Request payload as JSON string or Python list/dict object.

        path_params : dict | None, default=None
            Replace placeholders like `{lab_id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.timeout) for a single request.

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
            Replace placeholders like `{lab_id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.timeout) for a single request.

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
            Replace placeholders like `{lab_id}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.timeout) for a single request.

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
        Retrieves all data items from a `GET` endpoint.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        params : dict | None, default=None
            URL query parameters to include in the request. will be added as `?key=value` pairs in the URL.

        path_params : dict | None, default=None
            Replace placeholders like `{objectId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/cml/#wingpy.cisco.cml.CiscoModelingLabs.timeout) for a single request.

        Returns
        -------
        list[dict]
            A list of returned dictionaries from the GET endpoint.

            Similar to the root list in the Cisco Modeling Labs API JSON responses.
        """

        response = self.get(
            path,
            params=params,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        response_list = response.json()

        if not isinstance(response_list, list):
            raise UnsupportedMethodError(
                "The get_all method is only supported for endpoints returning a list"
            )

        return response_list
