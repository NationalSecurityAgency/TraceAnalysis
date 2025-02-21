project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/database-manager
    cargo build --release
    cp {{ project-root }}/target/release/dbmanager {{ build-dir }}/database-manager
    cp -r data {{ build-dir }}/database-manager/data

doc:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo doc --no-deps

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test --all-features

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    bin=${install}/bin
    share=${install}/share
    mkdir -p ${bin} ${share}
    ln -sf {{ build-dir }}/database-manager/dbmanager ${bin}/dbmanager
    ln -sf {{ build-dir }}/database-manager/data ${share}/database-manager

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    bin=${install}/bin
    share=${install}/share
    rm -f ${bin}/dbmanager ${share}/database-manager
    rm -rf {{ build-dir }}/database-manager
    cargo clean --release -p dbmanager
    cargo clean -p dbmanager
