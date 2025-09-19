from abc import ABC


class ApiClient(ABC):
    base_url: str | None = None
    """The base URL for the API."""
