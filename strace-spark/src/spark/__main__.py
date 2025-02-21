#! /usr/bin/env python3

"""Yet another strace parser."""

import json
import logging
import os
import sys
from signal import SIGINT, signal
from typing import Any

from ._logging import _get_log_macros
from .cli import CLI
from .parser import parse_event
from .parser.errors import ParsingError, UnknownFormatError
from .schema.events import EventJSONEncoder

# Globals
STOP_PROCESSING = False


# Setup Signal Handler
def sigint_handler(_signum: int, _frame: Any, logger: logging.Logger) -> None:
    """Signal Handler"""
    global STOP_PROCESSING  # pylint: disable W0603

    if STOP_PROCESSING:
        # Ctrl+C pressed twice, so the user probably really wants to cancel...
        sys.exit(1)

    logger.info("SIGINT received...")
    STOP_PROCESSING = True


def main() -> int:
    """Spark Main Loop"""

    # Parse CLI arguments
    cli = CLI()

    # Setup Logging
    logging.basicConfig(
        format="{levelname:<8}: {name} - {message}", style="{", level=cli.log_level
    )
    logger = logging.getLogger("spark.main")
    DEBUG, _, _, ERROR, _ = _get_log_macros(logger)

    # Setup handler for SIGINT assuming CLI arguments parsed correctly
    signal(SIGINT, lambda signum, frame: sigint_handler(signum, frame, logger))

    # Main processing loop
    with cli as (f_input, f_output):
        for line in f_input:
            # Check Interrupt
            if STOP_PROCESSING:
                logger.info("Stopping...")
                break

            line = line.strip()
            if "" == line:
                continue  # Go to next iteration

            try:
                event = parse_event(line)
                data = json.dumps(event, cls=EventJSONEncoder)
                DEBUG("serialized event: {}", data)
                f_output.write(data.encode())
                f_output.write(b"\n")

            except (NotImplementedError, ParsingError, UnknownFormatError) as e:
                ERROR("{}: {}", e.__class__.__name__, e)
                print(line, file=sys.stderr)

            except BrokenPipeError:
                devnull = os.open(os.devnull, os.O_WRONLY)
                if cli.output_file is None:
                    os.dup2(devnull, sys.stdout.fileno())
                    # TODO: Do i need to reset the cli.output_file if not stdout..?
                break

    return 0


# Runs when __name__ == "__main__"
sys.exit(main())
