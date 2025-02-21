"""Strace Events

This module describes three main event types:
 * Trace
 * Signal
 * Syscall

See each class description for more information.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from enum import IntEnum, auto
from json import JSONEncoder  # , JSONDecoder
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union
from uuid import UUID, uuid4


class ReturnStatus(IntEnum):
    """Enum representing the states of a syscall event."""

    SUCCESSFUL = auto()  #: Syscall finished with a valid return value.
    FAILED = auto()  #: Syscall did not return a valid value and *errno* was set.
    UNFINISHED = (
        auto()
    )  #: Syscall was interrupted by the kernel and is still processing.
    UNAVAILABLE = (
        auto()
    )  #: Syscall returned but strace failed to fetch the return value.
    DETACHED = auto()  #: Strace detached before the syscall could return.

    def __repr__(self: ReturnStatus) -> str:
        return f"<{self.__class__.__name__}.{self.name}>"


class EventType(IntEnum):
    """Enum for each type of event."""

    TRACE = auto()
    SIGNAL = auto()
    SYSCALL = auto()

    def __repr__(self: EventType) -> str:
        return f"<{self.__class__.__name__}.{self.name}>"


@dataclass
class _AbstractDataclass(ABC):
    """An abstract dataclass which doesn't allow instantiation of the base class."""

    def __new__(cls: Any, *_args: List[Any], **_kwargs: Dict[Any, Any]) -> Any:
        if cls in (_AbstractDataclass, cls.__bases__[0]):
            raise TypeError("Cannot instantiate abstract class.")
        return super().__new__(cls)


# Generic Type for Event.from_dict()
T = TypeVar("T", bound="Event")


@dataclass
class Event(_AbstractDataclass):
    """Abstract class for events to inherit from."""

    id: UUID = field(init=False, default_factory=uuid4)
    event_type: EventType = field(init=False)

    @classmethod
    def from_dict(cls: Type[T], obj: Dict[Any, Any]) -> T:
        """Constructs a ``Event`` from a ``dict``.

        :param obj: A ``dict`` with keys corresponding to fields of the
            ``Event``
        :raises ValueError: if any of the class fields are not valid keys in
            dictionary.
        :return: An instance of the ``Event``
        """
        return cls()._fill_class_fields(obj)

    def _fill_class_fields(self: T, obj: Dict[Any, Any]) -> T:
        """A helper method to fill in class attribute from a dictionary."""

        try:
            for f in fields(self):
                setattr(self, f.name, obj[f.name])
        except KeyError as e:
            raise ValueError(
                f"Invalid {self.__class__.__name__} Object: {repr(obj)}"
            ) from e

        return self


@dataclass
class Trace(Event):
    """An ``Event`` for messages from the tracing program."""

    #: The message from the tracing program.
    desc: Optional[str] = None

    def __post_init__(self: Trace) -> None:
        self.event_type = EventType.TRACE


#: A type alias representing the types of arguments in a syscall event. They will
#: be a ``str``, (``ArgType``, ...), or a {``str``: ``ArgType``}.
ArgType = Union[str, Tuple[Any, ...], Dict[str, Any]]


@dataclass
class Signal(Event):
    """An ``Event`` representing a Linux signal."""

    #: A ``str`` containing the type of the signal. For example ``SIGINT`` when
    #: a program receives ctrl+c.
    #:
    #: .. note::
    #:    ``TODO:`` Should this be a dedicated type? (I.e ``signal.SIGNALS``)
    signal: str
    #: A ``dict`` representing the siginfo structure.
    siginfo: Dict[str, ArgType]
    #: A process id associated with the signal. Defaults to ``None``.
    pid: Optional[int] = None

    def __post_init__(self: Signal) -> None:
        self.event_type = EventType.SIGNAL

    @classmethod
    def from_dict(cls: Type[Signal], obj: Dict[Any, Any]) -> Signal:
        """Constructs a ``Signal`` from a ``dict``.

        :param obj: See :py:meth:`spark.schema.events.Event.from_dict`.
        :raises ValueError: See :py:meth:`spark.schema.events.Event.from_dict`
        :returns: A ``Signal`` object with valid fields from ``obj`` filled in.
        """
        return cls("", {})._fill_class_fields(obj)


@dataclass
class Syscall(Event):
    """An ``Event`` representing a Linux syscall."""

    #: The name of the syscall.
    syscall: str
    #: Tuple of arguments passed to the syscall. May be an empty string if the
    #: syscall is unfinished. It will be an empty tuple if the syscall has no
    #: arguments.
    args: Tuple[ArgType, ...]
    #: The status of syscall event.
    return_status: ReturnStatus
    #: A process id associated with the syscall. Defaults to ``None``.
    pid: Optional[int] = None
    #: If the syscall was ``ReturnStatus.SUCCESSFUL``, then the return value will
    #: be stored as a string here. Otherwise, defaults to ``None``.
    return_value: Optional[str] = None
    #: If the syscall failed, the *errno* and description will be stored here.
    #: Defaults to ``None``.
    error: Optional[str] = None

    def __post_init__(self: Syscall) -> None:
        self.event_type = EventType.SYSCALL

    @classmethod
    def from_dict(cls: Type[Syscall], obj: Dict[Any, Any]) -> Syscall:
        """Constructs a ``Syscall`` from a ``dict``.

        :param obj: See :py:meth:`spark.schema.events.Event.from_dict`.
        :raises ValueError: See :py:meth:`spark.schema.events.Event.from_dict`
        :returns: A ``Signal`` object with valid fields from ``obj`` filled in.
        """
        syscall = cls("", (), ReturnStatus.UNAVAILABLE)._fill_class_fields(obj)
        syscall.return_status = ReturnStatus(syscall.return_status)
        return syscall


class EventJSONEncoder(JSONEncoder):
    """TODO"""

    def default(self: EventJSONEncoder, o: Any) -> Any:
        if is_dataclass(o):
            return asdict(o)
        if isinstance(o, UUID):
            return str(o)
        return super().default(o)
