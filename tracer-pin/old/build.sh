#!/bin/bash
PIN_ROOT="./pin-3.27"
g++ \
    -Wall \
    -Werror \
    -Wno-unknown-pragmas \
    -DPIN_CRT=1 \
    -fno-stack-protector \
    -fno-exceptions \
    -funwind-tables \
    -fasynchronous-unwind-tables \
    -fno-rtti \
    -DTARGET_IA32E \
    -DHOST_IA32E \
    -fPIC \
    -DTARGET_LINUX \
    -fabi-version=2 \
    -faligned-new \
    -I$PIN_ROOT/source/include/pin \
    -I$PIN_ROOT/source/include/pin/gen \
    -isystem $PIN_ROOT/extras/cxx/include \
    -isystem $PIN_ROOT/extras/crt/include \
    -isystem $PIN_ROOT/extras/crt/include/arch-x86_64 \
    -isystem $PIN_ROOT/extras/crt/include/kernel/uapi \
    -isystem $PIN_ROOT/extras/crt/include/kernel/uapi/asm-x86 \
    -I$PIN_ROOT/extras/components/include \
    -I$PIN_ROOT/extras/xed-intel64/include/xed \
    -O3 \
    -fomit-frame-pointer \
    -fno-strict-aliasing \
    -Wno-dangling-pointer \
    -c \
    -o \
    trace.o trace.cpp
g++ \
    -shared \
    -Wl,--hash-style=sysv $PIN_ROOT/intel64/runtime/pincrt/crtbeginS.o \
    -Wl,-Bsymbolic -Wl,--version-script=$PIN_ROOT/source/include/pin/pintool.ver \
    -fabi-version=2 \
    -o trace.so \
    trace.o \
    -L$PIN_ROOT/intel64/runtime/pincrt \
    -L$PIN_ROOT/intel64/lib \
    -L$PIN_ROOT/intel64/lib-ext \
    -L$PIN_ROOT/extras/xed-intel64/lib \
    -lpin \
    -lxed \
    $PIN_ROOT/intel64/runtime/pincrt/crtendS.o \
    -lpindwarf \
    -ldl-dynamic \
    -nostdlib \
    -lc++ \
    -lc++abi \
    -lm-dynamic \
    -lc-dynamic \
    -lunwind-dynamic
