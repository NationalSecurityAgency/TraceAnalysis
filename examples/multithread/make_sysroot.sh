#!/bin/bash

# Expects the first argument to be file listing dynamically loaded libraries used
# by a target program.

MAPS_FILE="${1:-./maps.out}"

if [[ ! -f "$1" ]]; then
    echo "USAGE: ./make_sysroot.sh </path/to/maps.out>" 1>&2
    exit 1
fi

awk '{print $1}' "$MAPS_FILE" \
    | grep -o "/.*$" \
    | sort \
    | uniq \
    | while read -r lib; do
          mkdir -p sysroot/"$(dirname "$lib")"
          cp -rpvL "$lib" sysroot/"$lib"
      done
