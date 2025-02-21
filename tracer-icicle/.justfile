project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTAL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/tracer-icicle
    cargo build --release
    cp {{ project-root }}/target/release/icicle_linux \
        {{ build-dir }}/tracer-icicle/icicle_linux

doc:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo doc --no-deps

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    build={{ clean(build-dir / "tracer-icicle") }}
    install={{ clean(install-root / install-prefix) }}
    bin=${install}/bin
    mkdir -p ${bin}
    ln -sf ${build}/icicle_linux ${bin}/icicle-linux-trace

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    bin=${install}/bin
    rm -rf {{ build-dir }}/tracer-icicle ${bin}/icicle-linux-trace
    cargo clean --release -p tracer-icicle
    cargo clean -p tracer-icicle
