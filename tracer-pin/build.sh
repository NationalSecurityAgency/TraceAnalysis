#! /bin/bash

# ln -s ./pin-#.##/ ./pin
PIN_ROOT="${PIN_ROOT:-./pin}"

make PIN_ROOT="$PIN_ROOT" TARGET="intel64" obj-intel64/pintool.so
make PIN_ROOT="$PIN_ROOT" TARGET="ia32" obj-ia32/pintool.so
