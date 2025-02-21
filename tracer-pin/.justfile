project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

pin-root := "/opt/pin"

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/tracer-pin
    make PIN_ROOT={{ pin-root }} TARGET="intel64" obj-intel64/pintool.so
    make PIN_ROOT={{ pin-root }} TARGET="ia32" obj-ia32/pintool.so
    cp obj-intel64/pintool.so {{ build-dir }}/tracer-pin/pintool-x86_64.so
    cp obj-ia32/pintool.so {{ build-dir }}/tracer-pin/pintool-i386.so
    cp -r scripts {{ build-dir }}/tracer-pin/

doc:

test:

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    plugins=${install}/lib/pin
    bin=${install}/bin
    mkdir -p ${plugins} ${bin}
    ln -sf {{ build-dir }}/tracer-pin/pintool-i386.so ${plugins}/pin-trace-i386.so
    ln -sf {{ build-dir }}/tracer-pin/pintool-x86_64.so ${plugins}/pin-trace-x86_64.so
    ln -sf {{ build-dir }}/tracer-pin/scripts/addr_to_file.py ${bin}/tracer-pin-addr-to-file

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    plugins=${install}/lib/pin
    bin=${install}/bin
    rm -rf ${plugins} ${bin}/tracer-pin-addr-to-file
    rm -rf {{ build-dir }}/tracer-pin obj-intel64/ obj-ia32/
