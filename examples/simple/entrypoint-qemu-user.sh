#!/bin/bash

# Some linker-loaders have issues parsing this
rm -f /etc/ld.so.cache

QEMU_ARCHS=(arm     aarch64 mips mips64   ppc     ppc64     m68k riscv64 sparc64)
      ABIS=(gnueabi gnu     gnu  gnuabi64 gnu     gnu       gnu  gnu     gnu    )
     ARCHS=(arm     aarch64 mips mips64   powerpc powerpc64 m68k riscv64 sparc64)

ANALYZE_ARCHS=(x86_64 i386 ppc arm aarch64)

# x86 (32/64) - Does not require extra linker path
for arch in {x86_64,i386}; do
    ARCH=$arch
    TARGET_PATH=/app/target/example-"$ARCH"
    OUTPUT_DIR=/app/out/"$ARCH"

    echo "[+] Architecture: $ARCH"

    # Create architecture specific directory
    mkdir -p $OUTPUT_DIR
    pushd $OUTPUT_DIR

    echo "[+] Tracing example program..."
    cat /app/target/input \
      | qemu-"$ARCH" \
             -trace target_mmap_complete \
             -one-insn-per-tb \
             -d plugin \
             -plugin $QEMU_PLUGINS/qemu-user-trace.so \
             $TARGET_PATH \
             2> mmap.txt

    echo "[+] Generating maps.out from memory map information..."
    qemu-user-generate-maps ./mmap.txt

    echo "[+] Collecting dynamically loaded libraries into sysroot..."
    /app/scripts/make_sysroot.sh ./maps.out

    echo "[+] Saving \"$TARGET_PATH\" in /app/out/exe..."
    echo $TARGET_PATH > exe

    echo "[+] Running tm-analyze on trace output..."
    tm-analyze -i ./trace.out
    mv out/ analyzed/

    popd
done

for i in ${!ARCHS[@]}; do
  ARCH=${ARCHS[$i]}
  TARGET_PATH=/app/target/example-"$ARCH"
  OUTPUT_DIR=/app/out/"$ARCH"

  echo "[+] Architecture: $ARCH"

  # Create architecture specific directory
  mkdir -p $OUTPUT_DIR
  pushd $OUTPUT_DIR

  echo "[+] Tracing example program..."
  cat /app/target/input \
      | qemu-"${QEMU_ARCHS[$i]}" \
             -trace target_mmap_complete \
             -one-insn-per-tb \
             -d plugin \
             -plugin $QEMU_PLUGINS/qemu-user-trace.so \
             -L /usr/"$ARCH"-linux-"${ABIS[$i]}" \
             $TARGET_PATH \
             2> mmap.txt

  echo "[+] Generating maps.out from memory map information..."
  qemu-user-generate-maps ./mmap.txt

  echo "[+] Collecting dynamically loaded libraries into sysroot..."
  /app/scripts/make_sysroot.sh ./maps.out

  echo "[+] Saving \"$TARGET_PATH\" in /app/out/exe..."
  echo $TARGET_PATH > exe

  if [[ " ${ANALYZE_ARCHS[*]} " =~ [[:space:]]${ARCH}[[:space:]] ]]; then
    echo "[+] Running tm-analyze on trace output..."
    tm-analyze -i ./trace.out
    mv out/ analyze/
  fi

  popd
done
