# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.
from dataclasses import dataclass
from typing import Literal

import httpx
from rich import traceback

from wingpy.interfaces import ApiClient


@dataclass
class WingpyException(Exception):
    """
    Base exception class for all wingpy exceptions.
    """

    message: str = ""

    def __post_init__(self):
        traceback.install()


@dataclass
class UnsupportedMethodError(WingpyException):
    """
    Raised when the an unsupported HTTP method is used on a client instance.

    Some APIs do not support all HTTP methods, and all methods must be
    implemented by client classes.

    Examples
    --------

    1. An API does not support the `PUT` HTTP method.
    2. The user calls the `.put()` method on the instance.
    3. The exception is raised.
    """

    method: Literal["DELETE", "GET", "PATCH", "POST", "PUT"] | None = None
    """The HTTP method that is not supported."""

    client: ApiClient | None = None
    """The name of the client class that does not support the method."""

    def __str__(self) -> str:
        msg = self.message

        if isinstance(self.client, ApiClient):
            client_name = self.client.__class__.__name__
        else:
            client_name = "this API"

        if self.method:
            msg += f"\n{self.method} not supported by {client_name}"

        return msg


@dataclass
class AuthenticationFailure(WingpyException):
    """
    Raised when API authentication fails.
    """

    response: httpx.Response | None = None
    """The HTTP response returned by the API."""

    def __str__(self) -> str:
        msg = self.message

        if self.response:
            code = self.response.status_code
            msg += f"\nAuthentication failed with status code: {code}"
            msg += f"\nResponse content: {self.response.text}"

        return msg


@dataclass
class InvalidEndpointError(WingpyException):
    """
    Raised when the specified API endpoint path is not valid for use in a URL.
    """

    client: ApiClient | None = None
    """The client class that is making the request."""

    endpoint_path: str | None = None
    """The invalid endpoint path."""

    def __str__(self) -> str:
        """
        Return a detailed error message including the full URL if possible.
        """

        msg = self.message

        if isinstance(self.client, ApiClient):
            client_name = self.client.__class__.__name__
            msg += f"\n{client_name}: Invalid endpoint path provided."

        if isinstance(self.client, ApiClient) and self.endpoint_path:
            msg += f"\nFull URL: {self.client.base_url}{self.endpoint_path}"
        else:
            if isinstance(self.client, ApiClient):
                msg += f"\nBase URL: {self.client.base_url}"
            if self.endpoint_path:
                msg += f"\nEndpoint path: {self.endpoint_path}"

        return msg


@dataclass
class UnexpectedPayloadError(WingpyException):
    """
    Raised when the API returned payload with unexpected data structure.
    """

    response: httpx.Response | None = None
    """The HTTP response returned by the API."""

    def __str__(self) -> str:
        msg = self.message

        if self.response:
            msg += f"\nUnexpected response: {self.response.text}"

        return msg


@dataclass
class URLSchemaError(WingpyException):
    """
    Raised when the provided base URL does not include a valid schema (http or https).
    """

    base_url: str | None = None
    """The invalid base URL."""

    def __str__(self) -> str:
        msg = self.message

        if self.base_url:
            msg += f"\nInvalid base URL: {self.base_url}"
            msg += "\nThe base URL must start with 'http://' or 'https://'."

        return msg


@dataclass
class URLNetlocError(WingpyException):
    """
    Raised when the provided base URL does not include a valid network location.
    """

    base_url: str | None = None
    """The invalid base URL."""

    def __str__(self) -> str:
        msg = self.message

        if self.base_url:
            msg += f"\nInvalid base URL: {self.base_url}"
            msg += "\nThe base URL must include a valid network location."

        return msg


@dataclass
class URLPathError(WingpyException):
    """
    Raised when the provided base URL ends with a forward slash (/).
    """

    base_url: str | None = None
    """The invalid base URL."""

    def __str__(self) -> str:
        msg = self.message

        if self.base_url:
            msg += f"Invalid base URL. Must not end with a '/': {self.base_url}"

        return msg


@dataclass
class MissingPathParameterError(WingpyException):
    """
    Raised when a required path parameter is missing for URL construction.
    """

    parameter: str | None = None
    """The missing path parameter."""

    available_params: str | None = None
    """The available path parameters."""

    client: ApiClient | None = None
    """The client class that is making the request."""

    endpoint_path: str | None = None
    """The endpoint path where the parameter is missing."""

    def __str__(self) -> str:
        msg = self.message

        if isinstance(self.client, ApiClient):
            client_name = self.client.__class__.__name__
            msg += f"{client_name}: Missing path parameter."

        if self.parameter:
            msg += f"\nMissing path parameter: {self.parameter}"
        if self.available_params:
            msg += f"\nAvailable parameters: {self.available_params}"
        if self.endpoint_path:
            msg += f"\nEndpoint path: {self.endpoint_path}"

        return msg


@dataclass
class InvalidResponseError(WingpyException):
    """
    Raised when the API returned an invalid or unexpected HTTP response.
    """

    response: httpx.Response | None = None
    """The HTTP response returned by the API."""

    def __str__(self) -> str:
        msg = self.message

        if self.response:
            code = self.response.status_code
            msg += f"\nInvalid response with status code: {code}"
            msg += f"\nResponse content: {self.response.text}"

        return msg
