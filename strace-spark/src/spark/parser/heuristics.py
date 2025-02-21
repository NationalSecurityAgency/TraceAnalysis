"""TODO"""

import re

from ..schema.events import EventType
from .errors import UnknownFormatError


def is_syscall(data: str) -> bool:
    """TODO"""
    return data.startswith("<...") or (re.match(r"^\w+\(", data) is not None)


def is_signal(data: str) -> bool:
    """TODO: Better heuristic?"""
    return data.startswith("---") and data.endswith("---")


proc_check = re.compile(r"Process\s+\d+\s+(?:attached|detached)")


def is_trace(data: str) -> bool:
    """TODO"""
    if data.startswith("+++") and data.endswith("+++"):
        return True

    if data[:7].lower() == "strace:":
        return True

    return proc_check.match(data) is not None


def guess_event_type(data: str) -> EventType:
    """TODO"""

    # Check for syscalls first because they show up the most often.
    if is_syscall(data):
        return EventType.SYSCALL

    if is_signal(data):
        return EventType.SIGNAL

    if is_trace(data):
        return EventType.TRACE

    raise UnknownFormatError("Data doesn't match known strace format!")
