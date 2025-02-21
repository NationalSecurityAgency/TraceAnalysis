"""Helper Functions for Logging"""

import logging
from functools import partial
from typing import Any, Callable, Dict, List, Tuple, TypeVar

BraceMessageType = TypeVar("BraceMessageType", bound="_BraceMessage")


# https://docs.python.org/3/howto/logging-cookbook.html#using-particular-formatting-styles-throughout-your-application
class _BraceMessage:
    def __init__(
        self: BraceMessageType, fmt: str, *args: List[Any], **kwargs: Dict[Any, Any]
    ) -> None:
        self.fmt = fmt
        self.args = args
        self.kwargs = kwargs

    def __str__(self: BraceMessageType) -> str:
        return self.fmt.format(*self.args, **self.kwargs)


def _log_debug(
    logger: logging.Logger, fmt: str, *args: List[Any], **kwargs: Dict[Any, Any]
) -> None:
    """TODO"""
    logger.debug(_BraceMessage(fmt, *args, **kwargs))


def _log_info(
    logger: logging.Logger, fmt: str, *args: List[Any], **kwargs: Dict[Any, Any]
) -> None:
    """TODO"""
    logger.info(_BraceMessage(fmt, *args, **kwargs))


def _log_warning(
    logger: logging.Logger, fmt: str, *args: List[Any], **kwargs: Dict[Any, Any]
) -> None:
    """TODO"""
    logger.warning(_BraceMessage(fmt, *args, **kwargs))


def _log_error(
    logger: logging.Logger, fmt: str, *args: List[Any], **kwargs: Dict[Any, Any]
) -> None:
    """TODO"""
    logger.error(_BraceMessage(fmt, *args, **kwargs))


def _log_critical(
    logger: logging.Logger, fmt: str, *args: List[Any], **kwargs: Dict[Any, Any]
) -> None:
    """TODO"""
    logger.critical(_BraceMessage(fmt, *args, **kwargs))


def _get_log_macros(
    logger: logging.Logger,
) -> Tuple[Callable, Callable, Callable, Callable, Callable]:
    """TODO"""
    return (
        partial(_log_debug, logger),
        partial(_log_info, logger),
        partial(_log_warning, logger),
        partial(_log_error, logger),
        partial(_log_critical, logger),
    )
