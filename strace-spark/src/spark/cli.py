"""A CLI for spark.

.. note::
   ``TODO:`` Explain usage...
"""

import logging
import os
import sys
from argparse import ArgumentParser, ArgumentTypeError
from typing import Any, BinaryIO, Optional, TextIO, Tuple, TypeVar

from ._logging import _get_log_macros


class CLIError(Exception):
    """Raised when invalid combination of command line arguments are specified."""


CLIType = TypeVar("CLIType", bound="CLI")


class CLI:
    """A class for handling input/output of ``spark``.

    Converts strace output into a serialized format, specifically JSON.
    The trace can be piped in from stdin or an input file can optionally
    be specified. If an output file is not specified, trace events will
    be emitted to stdout.
    """

    def __init__(self: CLIType) -> None:
        """
        Uses ``argparse`` to process command line arguments and returns a valid
        ``CLI`` instance. For more information on individual command line args run:

        .. code-block:: console
           
           $ python -m spark --help
        """
        description = (
            self.__doc__.rsplit("\n\n", maxsplit=1)[-1] if self.__doc__ else ""
        )
        parser = ArgumentParser(
            description=description,
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-i",
            "--input_file",
            type=_valid_file_path,
            help=(
                "Input file to read from and convert to structured output."
                + " Default: stdin"
            ),
        )
        parser.add_argument(
            "-o",
            "--output_file",
            type=_nonexistant_file_path,
            help="Output to write structured ouput to. Default: stdout",
        )
        parser.add_argument("-v", "--verbose", action="count", default=0)

        # Parse command line arguments
        args = parser.parse_args()
        self.input_file = args.input_file
        self.output_file = args.output_file
        self.rx: Optional[TextIO | BinaryIO] = None
        self.tx: Optional[TextIO | BinaryIO] = None

        # Create Class Logger
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        _, _, _, self.log_error, _ = _get_log_macros(self.logger)

        if args.verbose <= 5:
            self.log_level = logging.CRITICAL - (10 * args.verbose)
        else:
            self.log_level = logging.DEBUG

    def __enter__(self: CLIType) -> Tuple[TextIO, BinaryIO]:
        # Setup Input
        # TODO: use bytes for input file as well
        if self.input_file is None:
            self.rx = sys.stdin
        else:
            if os.isatty(sys.stdin.fileno()):
                # Input is not being piped in, so okay to use file.
                self.rx = open(self.input_file, "r", encoding="utf-8")
            else:
                raise CLIError(
                    "Cannot use input from pipe and input file at the same time!"
                )

        # Setup Output
        if self.output_file is None:
            self.tx = sys.stdout.buffer
        else:
            self.tx = open(self.output_file, "wb")

        return (self.rx, self.tx)

    def __exit__(self: CLIType, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        # Close input file if necessary
        if self.rx is not None and sys.stdin != self.rx:
            self.rx.close()

        # Close output file if necessary
        if self.tx is not None and sys.stdout.buffer != self.tx:
            self.tx.close()

        if exc_type is not None:
            return False

        return True


def _valid_file_path(path: str) -> str:
    """Helper function for checking argument values."""
    if not os.path.isfile(path):
        raise ArgumentTypeError(f"'{path}' is not a file.")

    return path


def _nonexistant_file_path(path: str) -> str:
    """Helper function for checking argument values."""
    if os.path.exists(path):
        raise ArgumentTypeError(f"'{path}' already exists!")

    return path
