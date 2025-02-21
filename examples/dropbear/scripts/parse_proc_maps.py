#! /usr/bin/env python3

import json
import os
import sys

if __name__ == "__main__":
    if 2 != len(sys.argv):
        print(f"Usage: {sys.argv[0]} <PID>")
        sys.exit(1)

    pid = sys.argv[1]
    mappings = {}
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            items = line.split()

            if len(items) < 1:
                continue
            range = items[0]

            if len(items) < 6:
                continue
            path = items[5]

            if os.path.exists(path):
                low, high = range.split("-")

                if path not in mappings:
                    mappings[path] = []

                mappings[path].append(int(low, base=16))
                mappings[path].append(int(high, base=16))

    for path, addrs in mappings.items():
        print(
            json.dumps(
                {
                    "name": path,
                    "low": hex(sorted(addrs)[0]),
                    "high": hex(sorted(addrs)[-1]),
                }
            )
        )
