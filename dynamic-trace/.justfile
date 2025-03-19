project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo build --release --all-features
    mkdir -p {{ build-dir }}/trace-management
    cp {{ project-root }}/target/release/tm-analyze {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-analyze-modeling {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-count   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-split   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-print   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-truncate   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-filter-pc   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-filter-time   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-mem-query   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-mem-server   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-find-pc   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-ftrace   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-strace   {{ build-dir }}/trace-management/
    cp {{ project-root }}/target/release/tm-index   {{ build-dir }}/trace-management/

doc:
    #!/usr/bin/env bash
    cargo doc --no-deps --all-features

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test --all-features

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    bin=${install}/bin
    mkdir -p ${bin}
    for tool in $( ls {{ build-dir }}/trace-management/ ); do
        ln -sf {{ build-dir }}/trace-management/$tool ${bin}/$tool
    done

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    bin=${install}/bin
    rm -rf {{ build-dir }}/trace-management ${bin}/trace-management
    cargo clean --release -p trace
    cargo clean -p trace
