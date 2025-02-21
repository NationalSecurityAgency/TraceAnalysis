project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo build --release

doc:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo doc --no-deps

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test

install:

clean:
    cargo clean --release -p ghidra-lifter
    cargo clean -p ghidra-lifter
