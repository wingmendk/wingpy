import sys as _sys

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
