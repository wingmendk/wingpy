"""
Backward compatibility shim for `wingpy.logging`.

Deprecated: use `wingpy.logging` instead.
"""

from wingpy.logging import logger, log_to_file, log_exception  # noqa: F401

logger.warning("This module is deprecated. Use `wingpy.logging` instead.")
