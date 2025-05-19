#!/bin/bash

TARGET_PATH=/app/target/example

echo "[+] Tracing example program..."

export LD_BIND_NOW=1 # ensure that in our trace, dynamic linking all occurs up front so that we can filter it out of our trace
cat /app/target/input | pin -t $PIN_PLUGINS/pin-trace-x86_64.so -- $TARGET_PATH

# for convenience, normalise the trace filename
mv trace.* trace.out

echo "[+] Generating maps.out from memory map information..."
cat maps.jsonl | jq -r '.name + " " + .low' > maps.out

echo "[+] Collecting dynamically loaded libraries into sysroot..."
/app/scripts/make_sysroot.sh ./maps.out

echo "[+] Saving <path/to/target> in /app/out/exe..."
echo $TARGET_PATH > ./exe


# we are going to filter out everything prior to libc_start_main

# first we identify the first tick of libc_start_main
echo "[+] Finding libc_start_main"
starttick=$(tm-ftrace --map maps.jsonl --sysroot sysroot -i trace.out | jq 'select (.name | contains("libc_start_main")) | .start_tick')

# then we filter the trace to remove from tick 0 until just a bit before we hit libc_start_main
echo "[+] Filtering to only code form libc_start_main onwards"
cat trace.out | tm-filter-time -o filtered.out -r 0:$((starttick-2))
cp trace.out unfiltered.out
cp filtered.out trace.out

mkdir -p out/memory
echo "[+] Indexing strings and memory from the filtered trace output"
tm-index -i trace.out --str-index out/memory/strings.index --st-index out/memory/spacetime.index -o /dev/null

echo "[+] Indexing dataflow from the filtered trace output..."
tm-analyze -i ./trace.out
mv out/ analyzed/
