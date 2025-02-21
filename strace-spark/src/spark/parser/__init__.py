"""TODO"""

from ..schema.events import Event, EventType, Trace
from .errors import UnreachableError
from .heuristics import guess_event_type
from .signal import parse_signal_event
from .syscall import parse_syscall_event
from .utils import extract_pid


def parse_event(data: str) -> Event:
    """The most generic parsing function because it does not make any assumptions
    about the data its attempting to parse. It tries to determine the event type
    and call the associated function for further processing.

    @param: TODO
    @return: TODO
    """

    # Removes pid from line for easier processing
    pid, data = extract_pid(data)
    event: Event

    event_type = guess_event_type(data)

    if EventType.SYSCALL == event_type:
        event = parse_syscall_event(data, pid)
    elif EventType.SIGNAL == event_type:
        event = parse_signal_event(data)
        event.pid = pid
    elif EventType.TRACE == event_type:
        event = Trace(desc=data)
    else:
        raise UnreachableError

    return event
