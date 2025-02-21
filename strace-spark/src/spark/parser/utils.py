"""TODO"""

from __future__ import annotations

import json
import logging
import re
import sys
from itertools import takewhile, tee
from typing import Iterable, Optional

from .._logging import _get_log_macros
from ..schema.events import ArgType
from .errors import ParsingError

logger = logging.getLogger(__name__)
DEBUG, _, WARN, _, _ = _get_log_macros(logger)


group_end_delim = {
    "(": ")",
    "[": "]",
    "{": "}",
    "<": ">",
    # FIXME: Really think about the repercussions of this
    ")": "(",
    "]": "[",
    "}": "{",
    ">": "<",
}


def split_args(data: str, delimiter: str = ",") -> list[str]:
    """TODO

    TODO: This function should have a `maxsplit` kwarg
    """

    if "" == data:
        return []

    # Janky hack since I'm having trouble dealing with the case when a group ends at
    # the last character in the arguments/data string...
    # data += " "

    arg_indices = [0]
    cursor = 0
    data_len = len(data)

    while cursor < data_len:
        char = data[cursor]

        if delimiter == char:
            DEBUG("comma at position: {}", cursor)
            arg_indices.append(cursor + 1)
        else:
            if char in group_end_delim:
                i = find_end_of_group(data[cursor:])
                cursor += i if i != -1 else 0

            elif '"' == char:
                i = find_end_of_string(data[cursor:])
                cursor += i if i != -1 else 0

            elif "/" == char and cursor != data_len - 1 and "*" == data[cursor + 1]:
                # NOTE: we can add 1 instead of 0 if we don't find the end of the
                # comment because we know the next 2 characters are '*/'. So +1 will
                # move to the '/' and the end of this while loop will move past that.
                i = find_end_of_comment(data[cursor:])
                cursor += i + 1 if i != -1 else 1

        cursor += 1

    # If we found any commas, add len(data) to arg_indices so that pairwise()
    # will split out all the arguments correctly.
    arg_indices.append(data_len)

    args = [data[x:y].rstrip(",").strip() for x, y in pairwise(arg_indices)]

    DEBUG("args: {}", args)
    DEBUG("Args Indices: {}", arg_indices)

    return args


def find_end_of_group(data: str) -> int:
    """TODO"""

    # This function should never be called with an unknown `group_delim`
    end_delim = group_end_delim[data[0]]
    cursor = 1
    data_len = len(data)

    DEBUG("finding group: '{}' in: <START>{}<END>", data[0], data[cursor:])

    while cursor < data_len:
        char = data[cursor]

        if end_delim == data[cursor : cursor + 1]:
            break

        if char in group_end_delim:
            i = find_end_of_group(data[cursor:])
            cursor += i if i != -1 else 0

        elif '"' == char:
            i = find_end_of_string(data[cursor:])
            cursor += i if i != -1 else 0

        elif "/" == char and cursor != data_len - 1 and "*" == data[cursor + 1]:
            i = find_end_of_comment(data[cursor:])
            cursor += i + 1 if i != -1 else 1

        cursor += 1

    return cursor if cursor < data_len else -1


def find_end_of_string(data: str) -> int:
    """TODO"""

    cursor = 1
    data_len = len(data)

    while cursor < data_len:
        char = data[cursor]

        if '"' == char:
            return cursor

        # Handle properly escaped characters
        if "\\" == char:
            if cursor != data_len - 1 and '"' == data[cursor + 1]:
                cursor += 2
                continue

        cursor += 1

    return cursor if cursor < data_len else -1


def find_end_of_comment(data: str) -> int:
    """
    TODO

    NOTE: this could be better... We don't really need to iterate pairwise,
    only when the next char is '*' which could possibly start the end of
    the comment.
    """

    # Behold my Fancy-ness
    *_, (i, _) = enumerate(takewhile(lambda x: tuple("*/") != x, pairwise(data)))
    cursor = i + 1 if 0 < i < len(data) - 2 else -1

    return cursor


# Handles both '[pid 12345] ' and '12345 '
pid_check = re.compile(r"^(?:(?:\[pid\s*)?(\d+)(?:\s*\]\s+)?)?(.+)$")


def extract_pid(data: str) -> tuple[Optional[int], str]:
    """TODO"""

    m = pid_check.search(data)

    if m is None:
        raise ParsingError("Pid regex did not match data!")

    pid_str, data = m.groups()
    data = data.strip()  # TODO: maybe improve regex rather than re-strip line?

    try:
        pid = int(pid_str) if pid_str is not None else None
    except ValueError as e:
        raise ParsingError(f"Couldn't convert pid '{pid_str}' to integer.") from e

    return pid, data


def parse_unit(data: str) -> ArgType:
    """TODO"""

    try:
        char = data[0]
        if '"' == char:
            return parse_string(data)
        if "[" == char:
            return parse_array(data)
        if "{" == char:
            return parse_dict(data)
        if "/*" in data:
            try:
                arg_str, comment = split_args(data, delimiter=" ")
                WARN("Skipping comment: {}", comment)
                return parse_unit(arg_str)
            except ValueError as e:
                raise ParsingError(
                    f"Unable to split argument from comment: {data}"
                ) from e

        return data

    except ParsingError as e:
        WARN("{}: {}", e.__class__.__name__, e)
        return data


def parse_string(data: str) -> str:
    """TODO"""

    try:
        # NOTE: assumes encasing `"` chars
        return json.loads(data.rstrip("..."))  # type: ignore
    except json.JSONDecodeError as e:
        # FIXME: Deal with strace string encodings
        # I.e. "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0 \347\0\0\0\0\0\0"...

        WARN("Parse string error: {}", e)
        WARN("Unable to decode string: {}", data)

        return data


def parse_array(data: str) -> tuple[ArgType, ...]:
    """TODO"""

    return tuple(parse_unit(arg) for arg in split_args(data.lstrip("[").rstrip("]")))


def parse_dict(data: str) -> dict[str, ArgType]:
    """TODO"""

    ret: dict[str, ArgType] = {}

    try:
        for arg in split_args(data.lstrip("{").rstrip("}")):
            k, v = arg.split("=", maxsplit=1)
            ret[k] = parse_unit(v)
    except ValueError as e:
        raise ParsingError(f"Invalid 'KEY=VALUE' pair in: {data}") from e

    return ret


# NOTE: Removing for now. Parsing intergers/file descriptors is going to
# be context dependent (I.e. based on which syscall and which argument it
# is.) I'm going to leave this to another program that could validate spark
# output and convert things that should be integers to their corresponding
# value. Also, this has the added bonus of getting to handle constants and
# file descriptors correctly.
# def parse_int(data: str) -> int:
#     try:
#         return int(data, base=16) if data.startswith("0x") else int(data)
#     except ValueError as e:
#         raise ParsingError(f"Unable to parse integer from {data}") from e

if sys.version_info[:3] >= (3, 10, 0):
    from itertools import pairwise as itertools_pairwise


def pairwise(iterable: Iterable) -> Iterable:
    """pairwise('ABCDEFG') --> AB BC CD DE EF FG

    NOTE: Uses the version from itertools if python version is >= 3.10
    """
    if sys.version_info[:3] >= (3, 10, 0):
        return itertools_pairwise(iterable)

    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)
