project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo build --release --all-features

doc:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo doc \
        -p dataflow \
        -p dataflow-core \
        -p dataflow-arango \
        -p dataflow-cbranch \
        -p dataflow-csv \
        -p dataflow-fntrack \
        -p dataflow-fpmodels \
        -p dataflow-jsonl \
        -p dataflow-pointsto \
        -p dataflow-syscalls \
        --all-features \
        --no-deps

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test \
        -p dataflow \
        -p dataflow-core \
        -p dataflow-arango \
        -p dataflow-cbranch \
        -p dataflow-csv \
        -p dataflow-fntrack \
        -p dataflow-fpmodels \
        -p dataflow-jsonl \
        -p dataflow-pointsto \
        -p dataflow-syscalls \
        --all-features
        
install:

clean:
    cargo clean --release \
        -p dataflow \
        -p dataflow-core \
        -p dataflow-arango \
        -p dataflow-cbranch \
        -p dataflow-csv \
        -p dataflow-fntrack \
        -p dataflow-fpmodels \
        -p dataflow-jsonl \
        -p dataflow-pointsto \
        -p dataflow-syscalls
    cargo clean \
        -p dataflow \
        -p dataflow-core \
        -p dataflow-arango \
        -p dataflow-cbranch \
        -p dataflow-csv \
        -p dataflow-fntrack \
        -p dataflow-fpmodels \
        -p dataflow-jsonl \
        -p dataflow-pointsto \
        -p dataflow-syscalls
