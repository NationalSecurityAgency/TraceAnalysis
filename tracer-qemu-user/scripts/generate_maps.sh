#!/bin/bash

MMAP_TXT="${1:-./mmap.txt}"
MMAP_DAT="${2:-./mmap.dat}"

if [[ ! -f "$MMAP_TXT" || ! -f "$MMAP_DAT" ]]; then
    echo "USAGE: $0 <mmap.txt> <mmap.dat>"
    exit 1
fi

sed 's/.*retaddr=0x//' mmap.txt \
    | while read -r addr; do
          grep "^0*$addr" mmap.dat
      done \
    | awk '$6 != "" {print $0}'\
    | sort \
    | uniq -f 5 \
    | awk '{print $6" 0x"$1}' \
    | sed 's/-[^-]*$//' \
          > maps.out
