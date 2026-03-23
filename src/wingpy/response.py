import httpx
from collections.abc import Mapping
from typing import Optional
from lxml import etree
from collections.abc import Sequence

from json.decoder import JSONDecodeError


class ResponseMapping(Mapping, httpx.Response):
    """
    Wraps an httpx.Response object to provide Mapping-like access to its JSON content.
    If the response content is not valid JSON, it will behave as an empty mapping.

    The `ResponseMapping` class is designed to treat API responses as mappings (dictionaries). We inherit from `httpx.Response`, `collections.abc.Mapping`, and implement the required methods (`__getitem__`, `__iter__`, and `__len__`)
    allowing you to access response data using keys. This is particularly useful for JSON responses, where you can access values directly using their corresponding keys.

    In addition we also implement `|`, `|=`, and `-` operators for merging and subtracting `ResponseMapping` objects, which can be useful when you want to combine data from multiple API responses.
    Basically you can treat the response like any `dict` object, but with all the benefits of the original `httpx.Response` (status code, headers, etc.) and additional functionality for working with the response data.

    Additionally, the equality operator (`==`) is implemented to allow for easy comparison between `ResponseMapping` objects and other mappings (like dictionaries).
    This means you can compare the JSON content of the response directly with another mapping, which can be very useful for testing and validation purposes.

    Parameters
    ----------
    response : httpx.Response
        The original HTTP response object to wrap. The content of this response will be parsed as JSON and made accessible through the mapping interface.
        If the content is not valid JSON, the mapping will behave as an empty dictionary.

    Examples
    --------
    ```python
    import httpx
    import wingpy
    response = httpx.Response(200, json={"key": "value"})
    wrapped_response = wingpy.ResponseMapping(response)
    print(wrapped_response["key"])
    'value'
    print(wrapped_response.status_code)
    200
    print(wrapped_response | {"new_key": "new_value"})
    {'key': 'value', 'new_key': 'new_value'}
    ```

    Raises
    ------
    TypeError
        If the `|`, `|=`, or `-` operators are used with an unsupported type (not a Mapping, dict, or ResponseMapping).

    """

    def __init__(self, response: httpx.Response):
        self._response = response
        """
        Cache the original `httpx.Response` object.
        """
        try:
            self._json_cache = response.json()
            """
            Attempt to parse the response content as JSON and cache it. If the content is not valid JSON, we will treat it as an empty dictionary.
            """
        except (JSONDecodeError, ValueError):
            self._json_cache = {}

    def __getitem__(self, key):
        """Allow access to JSON content using keys/subscript notation (e.g., response["key"]). If the key does not exist, it will raise a KeyError, just like a normal dictionary."""
        return self._json_cache[key]

    def __iter__(self):
        """Allow iteration over the keys of the JSON content, supporting for loops and other iterable contexts (iter())."""
        return iter(self._json_cache)

    def __len__(self):
        """Return the number of items in the JSON content. Support for len() function."""
        return len(self._json_cache)

    def __getattr__(self, name):
        """Allow access to attributes and methods of the original `httpx.Response` object transparently."""
        return getattr(self._response, name)

    def __repr__(self):
        """Provide a string representation of the `ResponseMapping` object, showing the original response and the cached JSON content."""
        return f"<ResponseMapping {self._response!r}>"

    def __or__(self, other):
        """
        Support the `|` operator for merging two `ResponseMapping` objects or a `ResponseMapping` with a regular mapping (like a dict).
        The result will be a new dictionary containing the combined key-value pairs, with values from the right-hand operand taking precedence in case of key conflicts.
        """
        if (
            isinstance(other, Mapping)
            or isinstance(other, dict)
            or isinstance(other, ResponseMapping)
        ):
            combined = dict(self._json_cache)
            combined.update(other)
            return combined
        else:
            raise TypeError(
                f"Unsupported operand type(s) for |: 'ResponseMapping' and '{type(other).__name__}'"
            )

    def __ror__(self, other):
        """
        Support the `|` operator for merging a regular mapping (like a dict) with a `ResponseMapping` object.
        The result will be a new dictionary containing the combined key-value pairs, with values from the right-hand operand taking precedence in case of key conflicts.
        """
        if (
            isinstance(other, Mapping)
            or isinstance(other, dict)
            or isinstance(other, ResponseMapping)
        ):
            combined = dict(other)
            combined.update(self._json_cache)
            return combined
        else:
            raise TypeError(
                f"Unsupported operand type(s) for |: '{type(other).__name__}' and 'ResponseMapping'"
            )

    def __ior__(self, other):
        """
        Support the `|=` operator for updating a `ResponseMapping` object with another mapping (like a dict) or another `ResponseMapping` object.
        The original `ResponseMapping` object will be modified in place, with values from the right-hand operand taking precedence in case of key conflicts.
        """
        if (
            isinstance(other, Mapping)
            or isinstance(other, dict)
            or isinstance(other, ResponseMapping)
        ):
            self._json_cache.update(other)
            return self
        else:
            raise TypeError(
                f"Unsupported operand type(s) for |=: 'ResponseMapping' and '{type(other).__name__}'"
            )

    def __sub__(self, other):
        """
        Support the `-` operator for removing keys from a `ResponseMapping` object based on another mapping (like a dict) or another `ResponseMapping` object.
        The result will be a new dictionary containing only the key-value pairs from the original `ResponseMapping` that do not have keys present in the right-hand operand.
        """
        if (
            isinstance(other, Mapping)
            or isinstance(other, dict)
            or isinstance(other, ResponseMapping)
        ):
            result = {k: v for k, v in self._json_cache.items() if k not in other}
            return result
        else:
            raise TypeError(
                f"Unsupported operand type(s) for -: 'ResponseMapping' and '{type(other).__name__}'"
            )

    def __eq__(self, other):
        """
        Support the equality operator (`==`) for comparing `ResponseMapping` objects with other mappings (like dictionaries) or other `ResponseMapping` objects.
        The comparison will be based on the JSON content of the response, allowing you to easily check if two responses have the same data regardless of their original `httpx.Response` objects.
        """
        if isinstance(other, ResponseMapping):
            return self._json_cache == other._json_cache
        if isinstance(other, Mapping) or isinstance(other, dict):
            return self._json_cache == other
        return False


class ResponseSequence(Sequence, httpx.Response):
    """
    Wraps an httpx.Response object to provide Sequence-like access to its JSON content.
    If the response content is not valid JSON or is not a list, it will behave as an empty sequence.

    The `ResponseSequence` class is designed to treat API responses as sequences (lists). We inherit from `httpx.Response`, `collections.abc.Sequence`, and implement the required methods (`__getitem__` and `__len__`)
    allowing you to access response data using indices. This is particularly useful for JSON responses that return lists, where you can access individual items directly using their corresponding indices.
    This class provides a convenient way to work with list-like API responses, while still retaining all the functionality of the original `httpx.Response` object.

    We also support the `+` and `-` operators for concatenating and removing items from `ResponseSequence` objects, which can be useful when you want to combine or filter data from multiple API responses.

    Additionally, the equality operator (`==`) is implemented to allow for easy comparison between `ResponseSequence` objects and other sequences (like lists).

    They play nice with lists as well as other `ResponseSequence` objects, so you can easily manipulate the response data as needed.

    Parameters
    ----------
    response : httpx.Response
        The original HTTP response object to wrap. The content of this response will be parsed as JSON and made accessible through the sequence interface.
        If the content is not valid JSON or is not a list, the sequence will behave as an empty list.

    Examples
    --------
    ```python
    import httpx
    import wingpy
    response = httpx.Response(200, json=[{"key": "value"}, {"key": "another value"}])
    wrapped_response = wingpy.ResponseSequence(response)
    print(wrapped_response[0])
    {'key': 'value'}
    print(wrapped_response.status_code)
    200
    print(wrapped_response + [{"key": "new value"}])
    [{'key': 'value'}, {'key': 'another value'}, {'key': 'new value'}]
    ```

    Raises
    ------
    TypeError
        If the `+` or `-` operators are used with an unsupported type (not a Sequence, list, or ResponseSequence).
    """

    def __init__(self, response: httpx.Response, use_response_key: str | None = None):
        self._response = response
        """
        Cache the original `httpx.Response` object.
        """

        self._use_response_key = use_response_key
        """
        If you're working with APIs that wrap their list responses in a top-level key (e.g., {"items": [...]} or {"response": [...]}) 
        and you want the `ResponseSequence` to operate directly on the list inside that key, then you can specify that key here.
        It's useful if you want to merge multiple pages of results together without having to manually extract the list from each response first.
        """

        try:
            self._json_cache = self._response.json()
            """
            Attempt to parse the response content as JSON and cache it. If the content is not valid JSON, we will treat it as an empty list.
            """
        except (JSONDecodeError, ValueError):
            self._json_cache = []

        if (
            self._use_response_key
            and isinstance(self._json_cache, dict)
            and self._use_response_key in self._json_cache
        ):
            self._json_cache = self._json_cache.get(self._use_response_key, [])

    def __getitem__(self, idx):
        """Allow access to JSON content using indices (e.g., response[0]). If the index is out of range, it will raise an IndexError, just like a normal list."""
        return self._json_cache[idx]

    def __len__(self):
        """Return the number of items in the JSON content. Support for len() function."""
        return len(self._json_cache)

    def __iter__(self):
        """Allow iteration over the items in the JSON content, supporting for loops and other iterable contexts (iter())."""
        return iter(self._json_cache)

    def __getattr__(self, name):
        """Delegate attribute access to the original HTTP response object."""
        return getattr(self._response, name)

    def __repr__(self):
        """Provide a string representation of the `ResponseSequence` object, showing the original response and the cached JSON content."""
        return f"<ResponseSequence({self._response!r})>"

    def __add__(self, other):
        """Support the `+` operator for combining a `ResponseSequence` with another sequence, list, or `ResponseSequence`."""
        if (
            isinstance(other, Sequence)
            or isinstance(other, list)
            or isinstance(other, ResponseSequence)
        ):
            combined = list(self._json_cache)
            combined.extend(other)
            return combined
        else:
            raise TypeError(
                f"Unsupported operand type(s) for +: 'ResponseSequence' and '{type(other).__name__}'"
            )

    def __radd__(self, other):
        """Support the `+` operator for combining a sequence, list, or `ResponseSequence` with a `ResponseSequence`."""
        if (
            isinstance(other, Sequence)
            or isinstance(other, list)
            or isinstance(other, ResponseSequence)
        ):
            combined = list(other)
            combined.extend(self._json_cache)
            return combined
        else:
            raise TypeError(
                f"Unsupported operand type(s) for +: '{type(other).__name__}' and 'ResponseSequence'"
            )

    def __iadd__(self, other):
        """Support the `+=` operator for extending a `ResponseSequence` with another sequence, list, or `ResponseSequence`."""
        if (
            isinstance(other, Sequence)
            or isinstance(other, list)
            or isinstance(other, ResponseSequence)
        ):
            self._json_cache.extend(other)
            return self
        else:
            raise TypeError(
                f"Unsupported operand type(s) for +=: 'ResponseSequence' and '{type(other).__name__}'"
            )

    def __eq__(self, other):
        """Support the equality operator (`==`) for comparing `ResponseSequence` objects with other sequences, lists, or `ResponseSequence` objects."""
        if isinstance(other, ResponseSequence):
            return self._json_cache == other._json_cache
        if isinstance(other, Sequence) or isinstance(other, list):
            return self._json_cache == other
        return False

    def __sub__(self, other):
        """Support the `-` operator for removing items from a `ResponseSequence` based on another sequence, list, or `ResponseSequence`."""
        if (
            isinstance(other, Sequence)
            or isinstance(other, list)
            or isinstance(other, ResponseSequence)
        ):
            result = [item for item in self._json_cache if item not in other]
            return result
        else:
            raise TypeError(
                f"Unsupported operand type(s) for -: 'ResponseSequence' and '{type(other).__name__}'"
            )


class XMLResponseMapping(Sequence, httpx.Response):
    """
    The `XMLResponseMapping` class is designed to treat XML API responses as sequences (lists). We inherit from `httpx.Response`, `collections.abc.Sequence`, and implement the required methods
    (`__getitem__` and `__len__`) allowing you to access XML elements by index, similar to a list. The class parses the XML content of the response and exposes the root's children as sequence items.
    If the XML cannot be parsed, indexing will raise an error.

    You can also access attributes and methods of the underlying `httpx.Response` and the XML root element transparently. This makes it easy to work with XML API responses as sequences, while still retaining all the features of the original response object.

    We use `lxml.etree` for XML parsing, which is a third-party library and provides a simple and efficient way to work with XML data.

    """

    def __init__(
        self, response: httpx.Response, namespaces: Optional[dict[str, str]] = None
    ):
        self._response = response
        """
        Cache the original `httpx.Response` object.
        """

        self._namespaces = namespaces or {}
        """
        Cache the provided namespaces for XML parsing.
        """

        try:
            self._root = etree.fromstring(response.text.strip().encode())
            """
            Attempt to parse the response content as XML and cache the root element. If the content is not valid XML, we will treat it as having no root (i.e., an empty sequence).
            """

        except etree.XMLSyntaxError:
            self._root = None

    def __getitem__(self, idx):
        """Allow access to XML elements using indices (e.g., response[0]). If the index is out of range or if the XML could not be parsed, it will raise an IndexError."""
        if self._root is None:
            raise IndexError("Index out of range: XML content could not be parsed.")
        return self._root[idx] if self._root is not None else None

    def __len__(self):
        """Return the number of XML elements in the root. Support for len() function."""
        return len(self._root) if self._root is not None else 0

    def __repr__(self):
        """Return a string representation of the XMLResponseMapping object."""

        return (
            f"<XMLResponseMapping({self._response!r}, namespaces={self._namespaces!r})>"
        )

    def __reduce__(self):
        """Support for pickling the XMLResponseMapping object."""
        return (XMLResponseMapping, (self._response, self._namespaces))

    def __getattr__(self, name):
        """Delegate attribute access to the original HTTP response object or the XML root element."""
        if hasattr(self._response, name):
            return getattr(self._response, name)
        elif hasattr(self._root, name):
            return getattr(self._root, name)
        else:
            raise AttributeError(
                f"'XMLResponseMapping' object has no attribute '{name}'"
            )


def convert_response(
    response: httpx.Response,
) -> ResponseMapping | ResponseSequence | XMLResponseMapping:
    """
    Wrap the response object to behave like a Mapping or Sequence,
    depending on its JSON or XML content.
    """

    ctype = response.headers.get("Content-Type", "")
    if "xml" in ctype or response.text.strip().startswith("<"):
        return XMLResponseMapping(response)

    try:
        json_data = response.json()
    except JSONDecodeError:
        return ResponseSequence(response)

    if isinstance(json_data, dict):
        return ResponseMapping(response)
    elif isinstance(json_data, list):
        return ResponseSequence(response)

    return ResponseSequence(response)
