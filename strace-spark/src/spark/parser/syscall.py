"""TODO"""

import logging
import re
from typing import Dict, NamedTuple, Optional, Tuple

from .._logging import _get_log_macros
from ..schema.events import ReturnStatus, Syscall
from .errors import ParsingError
from .utils import parse_unit, split_args

logger = logging.getLogger(__name__)
DEBUG, _, WARN, _, _ = _get_log_macros(logger)

resumed_pattern = re.compile(r"^<...\s+(\w+)\s+resumed>(.*)")

# TODO: refactor into class w/ attribute: unfinished_syscalls
PartialSyscall = NamedTuple("PartialSyscall", [("data", str), ("syscall", Syscall)])
deferred_events: Dict[Tuple[Optional[int], str], Optional[PartialSyscall]] = {}


def parse_syscall_event(data: str, pid: Optional[int] = None) -> Syscall:
    """
    Extract syscall info from strace output line

    returns: syscall object containing relevant data including
    name, arguments, return value, error (if present) and status
    """

    # Unfinished syscalls:
    if data.endswith("...>"):
        return parse_unfinished(data, pid)

    # Resumed Syscalls
    if data.startswith("<..."):
        data, syscall = get_unfinished_syscall_and_delete(data, pid)
    else:
        syscall = Syscall("", (), ReturnStatus.UNAVAILABLE)

    DEBUG("parsing syscall: {}", data)

    # Remove end bits: return value, ERRNO maybe, etc.
    end = split_args(data[::-1], delimiter="=")[0]
    data = data[: len(data) - len(end)].strip()
    end = end.rstrip("=").strip()[::-1]

    return_value, error, status = get_return_and_status(end)

    DEBUG("getting name and args: <START>{}<END>", data)

    m = re.match(r"^(\w+)\((.*)\)$", data)
    if m is None:
        raise ParsingError("Invalid syscall format.")

    name, arg_str = m.groups()
    args = tuple(parse_unit(arg) for i, arg in enumerate(split_args(arg_str)))

    syscall.syscall = name
    syscall.args = args
    syscall.return_status = status
    syscall.return_value = return_value
    syscall.error = error
    return syscall


# Group 1 - return value
# Group 2 (Optional) - return value context
# Group 3/4 (Optional) - return value description
# Group 5 (Optional) - error
#  * Group 6 - error code
#  * Group 7 (Optional) - errno description
G1_INT = r"[-]{0,1}[0-9]+"
G1_HEX = r"(?:0x){0,1}[0-9a-fA-F]+"
G2 = r"(<.+>)?"
G_3_4 = r"(:?\((.+)?\))?"
G6 = r"(E[A-Z]+)"
G7 = r"(.+)"
G_5_6_7 = rf"({G6}(?:\s{{1}}\({G7}\))?)?"
# TODO: is one space too restrictive between groups 4 and 5?

return_value_pattern = re.compile(rf"^(\?|{G1_INT}|{G1_HEX}){G2}\s*{G_3_4}{G_5_6_7}$")


def get_return_and_status(data: str) -> Tuple[str, Optional[str], ReturnStatus]:
    """TODO"""

    DEBUG("pattern: {}", return_value_pattern.pattern)
    DEBUG("data: {}", data)
    # Extract value and error, if they exist
    m = return_value_pattern.match(data)
    if m is not None:
        DEBUG("Matched return value!")
        value = (
            m.group(1)
            + (m.group(2) if m.group(2) is not None else "")
            + (m.group(3) if m.group(3) is not None else "")
        )
        error = m.group(5)  # TODO: separate error code and desc
    else:
        raise ParsingError("Couldn't parse return value...")

    # Update status
    status = ReturnStatus.SUCCESSFUL if error is None else ReturnStatus.FAILED

    return value, error, status


def parse_unfinished(data: str, pid: Optional[int] = None) -> Syscall:
    """TODO"""

    data = data.rstrip("<unfinished ...>").rstrip()

    # Handle continuation of a resumed syscall
    if data.startswith("<..."):
        m = re.match(resumed_pattern, data)
        if m is None:
            raise ParsingError("Unknown format of resumed syscall.")

        syscall_name, data = m.groups()

        key = (pid, syscall_name)

        p = deferred_events.get(key)
        if p is not None:
            partial = p
        else:
            partial = PartialSyscall("", Syscall("", (), ReturnStatus.UNFINISHED))

        deferred_events[key] = PartialSyscall(
            partial.data + data.strip(), partial.syscall
        )

        return partial.syscall

    # New unfinished syscall:
    m = re.match(r"^(\w+)\(", data)
    if m is None:
        raise ParsingError("Could not find syscall name in unfinished event.")

    (syscall_name,) = m.groups()

    key = (pid, syscall_name)
    p = deferred_events.get(key)
    if p is not None:
        WARN("Key Collision in `deferred_events`!")
        WARN("Previous Value: {} -> {}", key, p.data)
        WARN(" Current Value: {} -> {}", key, data)

        # deferred_events[key] = None  # Need to remove non-parsable syscall

        raise ParsingError(
            "Unfinished syscall was found before a previous one was parsed."
        )

    partial = PartialSyscall(
        data, Syscall(syscall_name, (), ReturnStatus.UNFINISHED, pid)
    )
    deferred_events[key] = partial
    DEBUG("Saved unfinished syscall: {}", partial)

    return partial.syscall


def get_unfinished_syscall_and_delete(
    data: str, pid: Optional[int] = None
) -> PartialSyscall:
    """TODO"""
    m = re.match(resumed_pattern, data)
    if m is None:
        raise ParsingError("Unknown format of resumed syscall.")

    syscall_name, data = m.groups()

    key = (pid, syscall_name)
    _partial = deferred_events.get(key)
    if _partial is not None:
        deferred_events[key] = None
        partial = _partial
    else:
        partial = PartialSyscall("", Syscall("", (), ReturnStatus.UNFINISHED))

    return PartialSyscall(partial.data + data.strip(), partial.syscall)
