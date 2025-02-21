#!/bin/bash

TARGET_PATH=/app/target/example

echo "[+] Tracing example program..."
cat /app/target/input | pin -t $PIN_PLUGINS/pin-trace-x86_64.so -- $TARGET_PATH
# NOTE: The line below is just because tracemadness expects a 'trace.out' file
mv trace.* trace.out

echo "[+] Generating maps.out from memory map information..."
cat maps.jsonl | jq -r '.name + " " + .low' > maps.out

echo "[+] Collecting dynamically loaded libraries into sysroot..."
/app/scripts/make_sysroot.sh ./maps.out

echo "[+] Saving <path/to/target> in /app/out/exe..."
echo $TARGET_PATH > ./exe

echo "[+] Running tm-analyze on trace output..."
tm-analyze -i ./trace.out
mv out/ analyzed/
