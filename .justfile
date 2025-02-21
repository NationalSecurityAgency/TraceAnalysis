just := just_executable()
project-root := env("TRACEANALYSIS_SRC", justfile_dir())
build-dir := env("BUILD_DIR", project-root / "build")
vendor-dir := env("VENDOR_DIR", "vendor")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

_default:
    @just --list

build target="all":
    #!/usr/bin/env bash
    if [ "{{ target }}" = "all" ]; then
        {{ just }} build-dir={{ build-dir }} build-all
    else
        {{ just }} build-dir={{ build-dir }} {{ target }}/build
    fi

[private]
build-all:
    {{ just }} build-dir={{ build-dir }} database-manager/build
    {{ just }} build-dir={{ build-dir }} dynamic-dataflow/build
    {{ just }} build-dir={{ build-dir }} dynamic-trace/build
    {{ just }} build-dir={{ build-dir }} ghidra-lifter/build
    {{ just }} build-dir={{ build-dir }} ghidra-tracemadness/build
    {{ just }} build-dir={{ build-dir }} strace-spark/build
    {{ just }} build-dir={{ build-dir }} tracer-icicle/build
    {{ just }} build-dir={{ build-dir }} tracer-panda/build
    {{ just }} build-dir={{ build-dir }} tracer-pin/build
    {{ just }} build-dir={{ build-dir }} tracer-qemu-user/build
    {{ just }} build-dir={{ build-dir }} tracer-unicorn/build

doc target="all":
    #!/usr/bin/env bash
    if [ "{{ target }}" = "all" ]; then
        {{ just }} build-dir={{ build-dir }} doc-all
    else
        {{ just }} {{ target }}/doc
    fi

[private]
doc-all:
    {{ just }} database-manager/doc
    {{ just }} dynamic-dataflow/doc
    {{ just }} dynamic-trace/doc
    {{ just }} ghidra-lifter/doc
    {{ just }} ghidra-tracemadness/doc
    {{ just }} strace-spark/doc
    {{ just }} tracer-icicle/doc
    {{ just }} tracer-panda/doc
    {{ just }} tracer-pin/doc
    {{ just }} tracer-qemu-user/doc
    {{ just }} tracer-unicorn/doc
    {{ just }} build-dir={{ build-dir }} docs/build

test target="all":
    #!/usr/bin/env bash
    if [ "{{ target }}" = "all" ]; then
        {{ just }} test-all
    else
        {{ just }} {{ target }}/test
    fi

[private]
test-all:
    {{ just }} database-manager/test
    {{ just }} dynamic-dataflow/test
    {{ just }} dynamic-trace/test
    {{ just }} ghidra-lifter/test
    {{ just }} ghidra-tracemadness/test
    {{ just }} strace-spark/test
    {{ just }} tracer-icicle/test
    {{ just }} tracer-panda/test
    {{ just }} tracer-pin/test
    {{ just }} tracer-qemu-user/test
    {{ just }} tracer-unicorn/test


install target="all":
    #!/usr/bin/env bash
    if [ "{{ target }}" = "all" ]; then
        {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} install-all
    else
        {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} {{ target }}/install
    fi

[private]
install-all:
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} database-manager/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} dynamic-dataflow/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} dynamic-trace/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} ghidra-lifter/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} ghidra-tracemadness/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} strace-spark/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} tracer-icicle/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} tracer-panda/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} tracer-pin/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} tracer-qemu-user/install
    {{ just }} build-dir={{ build-dir }} install-root={{ install-root }} install-prefix={{ install-prefix }} tracer-unicorn/install

clean target="all":
    #!/usr/bin/env bash
    if [ "{{ target }}" = "all" ]; then
        {{ just }} build-dir={{ build-dir }} clean-all
    else
        {{ just }} build-dir={{ build-dir }} {{ target }}/clean
    fi

[private]
clean-all:
    {{ just }} build-dir={{ build-dir }} database-manager/clean
    {{ just }} build-dir={{ build-dir }} dynamic-dataflow/clean
    {{ just }} build-dir={{ build-dir }} dynamic-trace/clean
    {{ just }} build-dir={{ build-dir }} ghidra-lifter/clean
    {{ just }} build-dir={{ build-dir }} ghidra-tracemadness/clean
    {{ just }} build-dir={{ build-dir }} strace-spark/clean
    {{ just }} build-dir={{ build-dir }} tracer-icicle/clean
    {{ just }} build-dir={{ build-dir }} tracer-panda/clean
    {{ just }} build-dir={{ build-dir }} tracer-pin/clean
    {{ just }} build-dir={{ build-dir }} tracer-qemu-user/clean
    {{ just }} build-dir={{ build-dir }} tracer-unicorn/clean
    {{ just }} build-dir={{ build-dir }} docs/clean

package:
    #!/usr/bin/env bash
    set -euxo pipefail
    tmp=`mktemp -d`
    package="${tmp}/traceanalysis_0.1-0"
    mkdir -p ${package}/DEBIAN
    cat << EOF > ${package}/DEBIAN/control
    Package: traceanalysis
    Version: 0.1-0
    Section: base
    Priority: optional
    Architecture: amd64
    Depends: libsqlite3-0, python3 (>= 3.10), python3 (<< 3.11)
    Recommends: openjdk-17-jdk, arangodb3 (= 3.11.6-1)
    Suggests: pandare (= 3.1.0), libosi (= 0.1.1)
    Maintainer: Placeholder <dummy@nowhere.invalid>
    Description: Trace Analysis
     Suite of tools for analyzing program execution traces
     
    EOF
    build="${package}/{{ build-dir }}/../"
    {{ just }} build-dir={{ build-dir }} install-root="${package}/" install-all
    mkdir -p ${build}
    cp -r {{ build-dir }} ${build}
    dpkg-deb --build ${package}
    cp ${package}.deb {{ project-root }}/
    rm -rf ${package}

#[private]
#install-system-build-deps:
#    #!/usr/bin/env bash
#    set -euxo pipefail
#    apt-get install --no-install-recommends -y `cat deps/ubuntu-2204-build-deps.txt`
#
#[private]
#install-system-deps:
#    #!/usr/bin/env bash
#    set -euxo pipefail
#    apt-get install --no-install-recommends -y `cat deps/ubuntu-2204-deps.txt`
#
#[group('vendor')]
#vendor-all: vendor-crates vendor-pypi
#
#[group('vendor')]
#vendor-crates:
#    #!/usr/bin/env bash
#    mkdir -p {{ vendor-dir }}/crates
#    cargo vendor --versioned-dirs --no-delete {{ vendor-dir }}/crates > {{ vendor-dir }}/crates/config.toml
#    
#[group('vendor')]
#vendor-pypi:
#    #!/usr/bin/env bash
#    mkdir -p {{ vendor-dir }}/pypi
#    # pip does not download build deps, so these need to be downloaded separately
#    pip download setuptools -d {{ vendor-dir }}/pypi
#    pip download ./tracer-unicorn[docs] -d {{ vendor-dir }}/pypi
#    pip download ./strace-spark[docs] -d {{ vendor-dir }}/pypi
#    
#[no-cd]
#[private]
#get-runtime-deps target:
#    #!/usr/bin/env bash
#    ldd {{ target }} | \
#    while read -r line; do \
#        echo "$line" | cut -d " " -f 1 | xargs dpkg -S 2>/dev/null | cut -d ":" -f 1; \
#    done | \
#    sort | \
#    uniq
    
#[no-cd]
#[private]
#get-all-runtime-deps:
#    #!/usr/bin/env bash
#    set -u
#    bins=`find {{ build-dir }} -type f -exec file '{}' \; | grep "dynamically linked" | cut -d ":" -f 1`
#    for bin in ${bins}; do
#        ldd "${bin}" | while read -r line; do
#            echo "$line" | cut -d " " -f 1 | xargs dpkg -S 2>/dev/null | cut -d ":" -f 1
#        done
#    done | sort | uniq
        
