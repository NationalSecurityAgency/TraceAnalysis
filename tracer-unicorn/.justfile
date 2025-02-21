project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/tracer-unicorn
    PIP_ROOT_USER_ACTION=ignore pip wheel . -w {{ build-dir }}/tracer-unicorn

doc:
    #!/usr/bin/env bash
    set -euxo pipefail
    PIP_ROOT_USER_ACTION=ignore pip install .[docs]
    make -C docs html

test:

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    PIP_ROOT_USER_ACTION=ignore pip install \
        --force-reinstall \
        --no-index \
        --find-links={{ build-dir }}/tracer-unicorn/ \
        --prefix={{ clean( install-root / "usr" ) }} \
        {{ build-dir }}/tracer-unicorn/unicorn_trace*.whl

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    rm -rf {{ build-dir }}/tracer-unicorn docs/build build/ *.egg *.egg-info/
    PIP_ROOT_USER_ACTION=ignore pip uninstall -y unicorn_trace || :
    
