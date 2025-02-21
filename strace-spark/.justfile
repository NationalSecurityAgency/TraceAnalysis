project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/strace-spark
    PIP_ROOT_USER_ACTION=ignore pip wheel . -w {{ build-dir }}/strace-spark

doc:
    #!/usr/bin/env bash
    PIP_ROOT_USER_ACTION=ignore pip install .[docs]
    make -C docs html

test:

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    PIP_ROOT_USER_ACTION=ignore pip install \
        --force-reinstall \
        --no-index \
        --find-links={{ build-dir }}/strace-spark/ \
        --prefix={{ clean( install-root / "usr" ) }} \
        {{ build-dir }}/strace-spark/spark*.whl

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    rm -rf {{ build-dir }}/strace-spark docs/build build/ *.egg *.egg-info/
    PIP_ROOT_USER_ACTION=ignore pip uninstall -y spark || :
