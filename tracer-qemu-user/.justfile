project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/tracer-qemu-user
    cargo build --release
    cp {{ project-root }}/target/release/libtracer_qemu_user.so {{ build-dir }}/tracer-qemu-user/libtrace.so
    cp -r scripts {{ build-dir }}/tracer-qemu-user

doc:
    #!/usr/bin/env bash
    cargo doc --no-deps

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    plugins=${install}/lib/qemu
    bin=${install}/bin
    mkdir -p ${plugins} ${bin}
    ln -sf {{ build-dir }}/tracer-qemu-user/libtrace.so ${plugins}/qemu-user-trace.so
    ln -sf {{ build-dir }}/tracer-qemu-user/scripts/generate_maps.sh ${bin}/qemu-user-generate-maps

clean:
    #!/usr/bin/env bash
    set -exuo pipefail
    install={{ clean(install-root / install-prefix) }}
    plugins=${install}/lib/qemu
    bin=${install}/bin
    cargo clean --release -p tracer-qemu-user
    cargo clean -p tracer-qemu-user
    rm -rf {{ build-dir }}/tracer-qemu-user *.o *.so *.d .libs/ ${plugins} \
        ${bin}/qemu-user-generate-maps
