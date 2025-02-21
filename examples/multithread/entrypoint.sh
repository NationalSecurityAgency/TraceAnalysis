#!/bin/bash

TARGET_PATH=/app/target/multithread64

echo "[+] Tracing example program..."
qemu-x86_64 \
    -trace target_mmap_complete \
    -one-insn-per-tb \
    -d plugin \
    -plugin /usr/local/lib/qemu/qemu-user-trace.so \
    $TARGET_PATH \
    2> mmap.txt

echo "[+] Generating maps.out from memory map information..."
qemu-user-generate-maps ./mmap.txt

echo "[+] Collecting dynamically loaded libraries into sysroot..."
/app/scripts/make_sysroot.sh ./maps.out

echo "[+] Saving <path/to/target> in /app/out/exe..."
echo $TARGET_PATH > ./exe

echo "[+] Splitting trace by threads..."
tm-split -i trace.out

largest_trace=`find . -type f -name "trace.0*" -printf '%s %p\n' | sort -nr | head -n 1 | cut -d ' ' -f 2`

echo "[+] Runnning tm-analyze on ${largest_trace} (largest thread)..."
tm-analyze -i ${largest_trace}
mv out/ analyzed/
