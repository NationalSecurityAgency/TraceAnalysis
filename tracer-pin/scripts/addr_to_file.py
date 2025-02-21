#! /usr/bin/env python3

"""
This script takes an `address` (in hex) and a path to a `maps.*.jsonl` and
attempts to find the associated file that was mapped to a range containing
`address`.
"""

from argparse import ArgumentParser
from orjson import loads
from os import path
from sys import stderr, exit

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('mapfile', help="Path to 'maps.jsonl'")
    parser.add_argument(
        'addr', help="Hex formatted address to look for in mappings")
    args = parser.parse_args()

    # Check path to maps file
    if not path.isfile(args.mapfile):
        print(f"ERROR - Bad file path: '{args.mapfile}'", file=stderr)
        exit(1)

    try:
        addr = int(args.addr, base=16)
    except ValueError:
        print(f"ERROR - Invalid hex address: '{args.addr}'", file=stderr)
        exit(1)

    mappings = []
    with open(args.mapfile, 'rb') as f:
        for line in f.read().split(b'\n'):
            if line:
                obj = loads(line)
                mappings.append((
                    obj["name"],
                    int(obj["low"], base=16),
                    int(obj["high"], base=16),
                ))

    for (name, low, high) in mappings:
        if low <= addr and addr <= high:
            print(f"{name} 0x{low:016x} 0x{high:016x}")
            exit(0)

    print(f"Address 0x{addr:0x} was not found...")
