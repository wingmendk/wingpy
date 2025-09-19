# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

import sys as _sys
from typing import Literal

from loguru._logger import Core as _Core
from loguru._logger import Logger as _Logger

logger = _Logger(
    core=_Core(),
    exception=None,
    depth=0,
    record=False,
    lazy=False,
    colors=False,
    raw=False,
    capture=True,
    patchers=[],
    extra={},
)
logger.add(_sys.stderr, level="WARNING")


def set_logging_level(level: str, sink=_sys.stderr):
    logger.remove()
    logger.add(sink, level=level)


def log_to_file(level: str, filename: str):
    sink = open(file=filename, mode="a")
    set_logging_level(level, sink=sink)


def log_exception(
    exception: Exception,
    severity: Literal[
        "TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"
    ] = "ERROR",
) -> None:
    """
    Log the exception message using the wingpy logger.

    Parameters
    ----------
    severity : str, optional
        The severity level to log the message at. Default is 'ERROR'.
    """
    if severity.upper() not in (
        "TRACE",
        "DEBUG",
        "INFO",
        "SUCCESS",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ):
        logger.error(
            f"Invalid severity level '{severity}' provided. Defaulting to 'ERROR'"
        )
        severity = "ERROR"

    logger.log(
        severity.upper(), exception.__class__.__name__ + ": " + exception.__str__()
    )
