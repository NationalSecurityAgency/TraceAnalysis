#! /bin/bash

# ln -s ./pin-#.##/ ./pin
PIN_ROOT="${PIN_ROOT:-./pin}"

make PIN_ROOT="$PIN_ROOT" clean
make PIN_ROOT="$PIN_ROOT" TARGET="ia32" clean
