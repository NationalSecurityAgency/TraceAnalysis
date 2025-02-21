#! /bin/bash

# NOTE: This script relies on external tools:
#  - clang-format >= v12
#  - fd (https://crates.io/crates/fd-find)

if [[ ! -f $(command -v clang-format ) ]]; then
    >&2 echo "Error: 'clang-format' not found..."
    exit 1
fi

TEMP_DIR=".format"
if [ -d "$TEMP_DIR" ]; then
    rm -r "$TEMP_DIR"
fi

mkdir "$TEMP_DIR"

for path in $(fd "\.(c|cpp|h)$"); do
    DIR=$(dirname "$path")
    FILE=$(basename "$path")
    clang-format "$path" > "$TEMP_DIR/$FILE"
    mv "$TEMP_DIR/$FILE" "$DIR/$FILE"
done
