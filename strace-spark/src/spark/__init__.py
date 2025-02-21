"""An strace parsing library.

Spark is a python library and command line tool for converting strace logs into
a structured format. Currently the only supported format is JSON.

There are two important modules provided by spark:

* :doc:`spark.parser`
* :doc:`spark.schema.events`

The events schema describes the structure of each event type. Currently there
are Trace events for things like when strace attaches/detaches from a
process. Then there are Signal events which are denoted by ``---`` at the front
and end of a line. These are usually found with a *SIGNUM* constant and an
enumerated ``siginfo`` structure. Finally there is the Syscall event which is the
majority of what is output by strace. Each event will have at least a name and
some arguments.

The parser module is a collection of utility functions all wrapped up into a
``parse_event`` function. This function take a string and does its best to
return one of the event types mentioned above or ``None`` if the format is
unknown.

.. note::
   ``TODO:`` Add an example.
"""

import logging

from .parser import parse_event  # noqa
from .schema.events import EventType, Signal, Syscall, Trace  # noqa

logging.getLogger(__name__).addHandler(logging.NullHandler())
