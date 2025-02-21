# Simple Test Program

example:
	gcc -g -O0 -o example example.c

multiarch:
	arm-linux-gnueabi-gcc -g -O0 -o example-arm example.c; \
	mips64-linux-gnuabi64-gcc -g -O0 -o example-mips64 example.c; \
	gcc -g -O0 -o example-x86_64 example.c; \
	gcc -g -O0 -m32 -o example-i386 example.c; \
	m68k-linux-gnu-gcc -g -O0 -static -o example-m68k example.c; \
	for arch in aarch64 mips powerpc powerpc64 riscv64 sparc64; do \
		$$arch-linux-gnu-gcc -g -O0 -o example-$$arch example.c; \
	done

.PHONY: clean all

all: example multiarch

clean:
	rm -f example example-*
