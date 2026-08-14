# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import os
from ssl import SSLContext
from time import sleep
from typing import Any, Callable
from urllib.parse import urlencode

from packaging.version import Version

from wingpy.base import RestApiBaseClass
from wingpy.exceptions import (
    AuthenticationFailure,
    InvalidJobError,
    UnexpectedPayloadError,
    UnsupportedMethodError,
)
from wingpy.logging import log_exception, logger
from wingpy.response import ResponseMapping, ResponseSequence


class CiscoSNA(RestApiBaseClass):
    """
    Interact with the Cisco Secure Network Analytics API.

    Parameters
    ----------

    base_url : str | None, default=None
        Base URL of the API including `https://`.

        Overrides the environment variable `WINGPY_SNA_BASE_URL`.

    username : str | None, default=None
        Username for API authentication.

        Overrides the environment variable `WINGPY_SNA_USERNAME`.

    password : str | None, default=None
        Password for API authentication.

        Overrides the environment variable `WINGPY_SNA_PASSWORD`.

    tenant_name : str | None, default=None
        The name of the tenant to query.

        Overrides the environment variable `WINGPY_SNA_TENANT_NAME`.

        If neither the parameter or environment variable are set, the first or only available tenant is used.

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
    from wingpy import CiscoSNA
    sna = CiscoSNA(
        base_url="https://sna.example.com",
        username="example_username",
        password="example_password",
    )
    tags = sna.get_all("/sw-reporting/v1/tenants/{tenantId}/customHosts/tags")
    print(f"Retrieved {len(tags)} tags")
    ```
    """

    RETRY_RESPONSES = []
    """
    No explicit retry reponses are defined for Cisco Secure Network Analytics.
    """

    MAX_CONNECTIONS = 10
    """
    The maximum number of concurrent connections opened to the Cisco Secure Network Analytics API.

    1 connection will be used for general synchronous requests.

    9 connections will be used for parallel asynchronous requests.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        tenant_name: str | None = None,
        verify: SSLContext | bool = True,
        timeout: int = 10,
        retries: int = 3,
    ):
        # Allow parameters to be passed directly or fallback to environment variables
        self.sna_url = base_url or os.getenv("WINGPY_SNA_BASE_URL")
        """
        The base URL for the Cisco Secure Network Analytics API.

        If not provided, it will be read from the environment variable `WINGPY_SNA_BASE_URL`.
        """

        self.username = username or os.getenv("WINGPY_SNA_USERNAME")
        """
        The username for authentication.

        If not provided, it will be read from the environment variable `WINGPY_SNA_USERNAME`.
        """

        self.password = password or os.getenv("WINGPY_SNA_PASSWORD")
        """
        The password for authentication.

        If not provided, it will be read from the environment variable `WINGPY_SNA_PASSWORD`.
        """

        self.tenant_name = tenant_name or os.getenv("WINGPY_SNA_TENANT_NAME")
        """
        The name of the tenant to query.

        If not provided, it will be read from the environment variable `WINGPY_SNA_TENANT_NAME`.

        If neither the parameter or environment variable are set, the first or only available tenant is used.
        """

        if not self.sna_url:
            raise ValueError(
                "Cisco Secure Network Analytics base_url must be provided either as argument or environment variable"
            )

        if not self.username or not self.password:
            raise ValueError(
                "Cisco SNA username and password must be provided either as arguments or environment variables"
            )

        self.token: str | None = None
        """
        The authentication token for Cisco SNA.
        """

        self.version: Version = Version("0.0")
        """
        The version of the Cisco Secure Network Analytics API.
        """

        super().__init__(
            base_url=self.sna_url,
            auth_lifetime=1800,
            auth_refresh_percentage=0.9,
            http2=True,
            verify=verify,
            timeout=timeout,
            retries=retries,
            headers={
                "Content-Type": "application/json",
                # `Accept` header is not supported
            },
        )

        self.path_params: dict = {}
        """
        A dictionary of path parameters to be used in the API path of each request.

        These parameters will be merged with any `path_params` dict passed to the request.

        `{tenantId}` is automatically resolved based on the [`tenant_name`](https://wingpy.automation.wingmen.dk/api/sna/#wingpy.cisco.sna.CiscoSNA) passed to the constructor.
        """

    def _authenticate(self) -> ResponseMapping | None:
        """
        Retrieves and stores a bearer token by authenticating with username and password
        using URL-encoded form payload.

        Warnings
        --------
        This protected method is only meant to be called internally.

        See also
        --------
        For proactive authentication see [`CiscoSNA.authenticate()`](https://wingpy.automation.wingmen.dk/api/sna/#wingpy.cisco.sna.CiscoSNA.authenticate)

        Returns
        -------
        ResponseMapping
            The response object from the authentication request.
        """

        if not self.username or not self.password:
            raise ValueError(
                "Username and password must be provided for authentication"
            )

        auth_payload = urlencode({"username": self.username, "password": self.password})

        auth_headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = self.request(
            "POST",
            "/token/v2/authenticate",
            data=auth_payload,
            headers=auth_headers,
            params=None,
            path_params=None,
            timeout=None,
            auth=None,
            is_auth_endpoint=True,
        )

        response.raise_for_status()

        if response.status_code != 200:
            error = AuthenticationFailure(
                message="Authentication failed",
                response=response,
            )
            log_exception(error)
            raise error

        # Cookie is set automatically by httpx client
        # Assign directly to attribute to support JWT parsing
        self.token = response.cookies.get("stealthwatch.jwt")

        # XSRF token in dedicated header is mandatory from version 7.3.2
        if xsrftoken := response.cookies.get("XSRF-TOKEN"):
            self.headers["X-XSRF-TOKEN"] = xsrftoken

        return response

    def _refresh_auth(self) -> None:
        """
        No dedicated authentication token refresh mechanism is available for
        Cisco Secure Network Analytics.
        """
        self.authenticate()

    @property
    def is_authenticated(self) -> bool:
        """
        Check if the client is authenticated.
        """
        return self.token is not None

    def _after_auth(self, **kwargs) -> None:
        """
        Handle post-authentication actions:

        - Update session lifetime
        - Extract tenant ID
        """

        # Token timeout shape can vary
        self.update_lifetime_from_jwt()

        # Find tenant ID
        tenant_rsp = self.request(
            "GET",
            "/sw-reporting/v1/tenants",
            data=None,
            params=None,
            path_params=None,
            headers=None,
            timeout=None,
            is_auth_endpoint=True,
            auth=None,
        )

        # Expected format:
        # {
        #   "data": [
        #     {
        #       "displayName": "my_tenant",
        #       "id": 301
        #     },
        #     {
        #       "displayName": "my_other_tenant",
        #       "id": 302
        #     }
        #   ]
        # }
        if (
            not isinstance(tenant_rsp, ResponseMapping)
            or len(tenant_rsp.get("data", [])) == 0
            or "id" not in tenant_rsp["data"][0]
        ):
            error = UnexpectedPayloadError(
                f"Unable to find tenants in JSON payload: {list(tenant_rsp.keys())}",
                response=tenant_rsp,
            )
            log_exception(error)
            raise error

        # If a specific tenant name is provided, find the ID and store it as path parameter
        if self.tenant_name:
            self.path_params.pop("tenantId", None)
            for tenant in tenant_rsp["data"]:
                if tenant["displayName"] == self.tenant_name:
                    logger.info(f"Using specified tenant: {self.tenant_name}")
                    self.path_params["tenantId"] = tenant["id"]
                    break
            if "tenantId" not in self.path_params:
                raise ValueError(f"Tenant '{self.tenant_name}' not found.")

        # If no tenant is provided, default to the first (or only)
        else:
            logger.info(f"Using default tenant: {tenant_rsp['data'][0]['displayName']}")
            self.path_params["tenantId"] = tenant_rsp["data"][0]["id"]

    def get(
        self,
        path: str,
        *,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> ResponseMapping | ResponseSequence:
        """
        Send an HTTP `GET` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        path_params : dict | None, default=None
            Replace placeholders like `{tagId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.timeout) for a single request.

        Returns
        -------
        ResponseMapping | ResponseSequence
            The [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence)
            object from the request.
        """

        response = self.request(
            "GET",
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

    def post(
        self,
        path: str,
        *,
        data: str | dict | list | None,
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> ResponseMapping | ResponseSequence:
        """
        Send an HTTP `POST` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : str | dict | list | None
            Request payload as JSON string or Python list/dict object.

        path_params : dict | None, default=None
            Replace placeholders like `{tagId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.timeout) for a single request.

        Returns
        -------
        ResponseMapping | ResponseSequence
            The [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence)
            object from the request.
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
    ) -> ResponseMapping | ResponseSequence:
        """
        Send an HTTP `PUT` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        data : str | dict | list | None
            Request payload as JSON string or Python list/dict object.

        path_params : dict | None, default=None
            Replace placeholders like `{tagId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.timeout) for a single request.

        Returns
        -------
        ResponseMapping | ResponseSequence
            The [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence)
            object from the request.
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
        !!! failure "HTTP PATCH is not supported by Cisco Secure Network Analytics"

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
    ) -> ResponseMapping | ResponseSequence:
        """
        Send an HTTP `DELETE` request to the specified path.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        path_params : dict | None, default=None
            Replace placeholders like `{tagId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.timeout) for a single request.

        Returns
        -------
        ResponseMapping | ResponseSequence
            The [`ResponseMapping`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseMapping) or [`ResponseSequence`](https://wingpy.automation.wingmen.dk/api/response/#wingpy.response.ResponseSequence)
            object from the request.
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
        path_params: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> list:
        """
        Secure Network Analytics does not use pagination.

        Response data is placed in the `data` element by the API.

        Some list-data is nested further by the API In those
        cases the actual list is extracted and returned.

        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.

        path_params : dict | None, default=None
            Replace placeholders like `{tagId}` in the URL path with actual values.

            Will be combined with [self.path_params](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.path_params) before sending request.

        headers : dict | None, default=None
            HTTP headers to be sent with the request.

            Will be combined with [self.headers](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.headers) before sending request.

        timeout : int | None, default=None
            Override the standard timeout timer [self.timeout](https://wingpy.automation.wingmen.dk/api/secure-network-analytics/#wingpy.cisco.sna.CiscoSNA.timeout) for a single request.

        Returns
        -------
        list[dict]
            A list-version of returned data.
        """

        response = self.get(
            path,
            path_params=path_params,
            headers=headers,
            timeout=timeout,
        )

        if isinstance(response, ResponseSequence):
            result = list(response)
        elif isinstance(response, ResponseMapping):
            if isinstance(response["data"], list):
                result = response["data"]
            elif isinstance(response["data"], dict):
                # Some endpoints include a summary as the first element
                # Use the last element
                *_, result = iter(response["data"].values())

        else:
            error = UnexpectedPayloadError(
                "Unable to retrieve list-based data", response=response
            )
            log_exception(error)
            raise error

        logger.debug(f"Received {len(result)} total items from {path}")
        return result

    def wait_for(
        self,
        func: Callable,
        path: str,
        on_complete: Callable | None = None,
        **kwargs,
    ) -> str | Any:
        """
        Provides easy access to the result of job generating APIs.
        These start asycronous jobs in the background where status can be queried periodically.
        When the job is done a new URL path is returned or passed to another callable.

        Examples
        --------
        By default a URL path for the final result is returned. You can then use get or get_all with it.
        ```python
        query = {
            "startDateTime": "2026-08-11T08:00:00Z",
            "endDateTime": "2026-08-11T08:00:00Z",
        }
        flow_result_path = sna.wait_for(
            sna.post,
            "/sw-reporting/v2/tenants/{tenantId}/flows/queries",
            data=query,
        )
        flows = sna.get_all(flow_result_path)
        ```

        Using the on_complete hook automatically runs that function with the returned path:
        ```python
        query = {
            "startTime": "2026-08-11T08:00:00.000",
            "endTime": "2026-08-11T09:00:00.000",
        }
        top_hosts = sna.wait_for(
            sna.post,
            "/sw-reporting/v1/tenants/{tenantId}/flow-reports/top-hosts/queries",
            data=query,
            on_complete=sna.get_all,
        )
        ```

        Parameters
        ----------
        func : Callable
            The initial method that creates the job.

        path : str
            The API endpoint path to send the request to.

        on_complete : Callable
            A method to call with the job result URL path after waiting for it to become ready.

        Other parameters
        ----------------

        **kwargs :
            Any keyword parameters passed on to the func, ie. headers, params, ...

        Returns
        -------
        str
            URL path for accessing the final result.

        Any
            Result from on_complete Callable passed through.
        """

        response = func(path, **kwargs)

        if "/v1/" in path and "/queries" in path and response.status_code == 200:
            result_path = self._get_query_result_path_v1(response)
        elif (
            "/v2/" in path
            and "/queries" in path
            and response.status_code == 201
            and "location" in response.headers
        ):
            result_path = self._get_query_result_path_v2(response)
        else:
            error = InvalidJobError(
                "Unable to determine API job type.",
                response=response,
            )
            log_exception(error)
            raise error
        if on_complete:
            return on_complete(result_path)
        else:
            return result_path

    def _get_query_result_path_v1(self, response: ResponseMapping) -> str:
        """
        Queries the status of a Reporting API version 1 job until completed and finds the final result path.

        Parameters
        ----------
        response : ResponseMapping
            The response of the POST request that created the query.

        Returns
        -------
        str
            URL path for accessing the final result.
        """

        # v1 status is available by adding the query ID as suffix
        query_path = response.url.path
        query_id = response["data"]["queryId"]
        job_status_path = f"{query_path}/{query_id}"

        # v2 results are avaiable /queries/xxyyzz is available at /results/xxyyzz
        result_path = job_status_path.replace("/queries/", "/results/")

        # Query status until completed
        while True:
            sleep(1)
            job_response = self.get(job_status_path)

            # Example v1 response:
            # {
            #   "data": {
            #     "queryId": "6a7af913782f23084d65cfbb", # pragma: allowlist secret
            #     "status": "COMPLETED"
            #   }
            # }
            status = job_response.get("data", {}).get("status")

            if status == "COMPLETED":
                return result_path
            elif status == "IN_PROGRESS":
                continue
            else:
                raise UnexpectedPayloadError("Unable to gather query status.")

    def _get_query_result_path_v2(self, response: ResponseMapping) -> str:
        """
        Queries the status of a Reporting API version 2 job until completed and finds the final result path.

        Parameters
        ----------
        response : ResponseMapping
            The response of the POST request that created the query.

        Returns
        -------
        str
            URL path for accessing the final result.
        """

        # v2 status is available at the location header URL
        location_path = str(response.headers.get("location")).removeprefix(
            self.base_url
        )
        # ... but the provided path contains an invalid path prefix /smc-core/rest
        job_status_path = location_path.removeprefix("/smc-core/rest")

        # v2 results are available by adding /results as suffix
        result_path = job_status_path + "/results"

        # Query status until completed
        while True:
            sleep(1)
            job_response = self.get(job_status_path)

            # Example v2 response:
            # {
            #   "data": {
            #     "query": {
            #       "id": "6a7af7a8782f23084d65cfb2", # pragma: allowlist secret
            #       "domainId": "301",
            #       "percentComplete": 100.0,
            #       "status": "COMPLETED"
            #     }
            #   }
            # }
            status = job_response.get("data", {}).get("query", "{}").get("status")

            if status == "COMPLETED":
                return result_path
            elif status == "IN_PROGRESS":
                continue
            else:
                raise UnexpectedPayloadError("Unable to gather query status.")
