"""TODO"""

import re

from ..schema.events import Signal
from .errors import ParsingError
from .utils import parse_dict

sig_check = re.compile(r"^---\s+(S[A-Z]+)\s+(?:(\{.+\}))?\s+---$")


def parse_signal_event(data: str) -> Signal:
    """TODO"""
    m = sig_check.search(data)

    if m is None:
        raise ParsingError("Data does not match Signal format!")

    signal, arg_str = m.groups()

    return Signal(signal, parse_dict(arg_str))
