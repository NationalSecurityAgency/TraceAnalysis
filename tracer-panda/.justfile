project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTAL_PREFIX", "usr/local")

build +archs="all":
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/tracer-panda
    archs=({{ archs }})
    if [ "${#archs[@]}" -eq 1 ] && [ "${archs[0]}" = "all" ]; then
        archs=("aarch64" "arm" "i386" "mips" "mipsel" "ppc" "x86_64")
    fi
    for arch in "${archs[@]}"; do
        case "${arch}" in
            "aarch64" | "arm" | "i386" | "mips" | "x86_64")
                cargo build \
                    --release \
                    --no-default-features \
                    -F panda-${arch}
                cargo build \
                    --release \
                    --no-default-features \
                    -F tracer-panda-bin,panda-${arch} \
                    --bin panda-trace-${arch}
                cp {{ project-root }}/target/release/libtracer_panda.so \
                    {{ build-dir }}/tracer-panda/panda_madpanda-${arch}.so
                cp {{ project-root }}/target/release/panda-trace-${arch} \
                    {{ build-dir }}/tracer-panda/
                ;;
            "mipsel" | "ppc")
                cargo build \
                    --release \
                    --no-default-features \
                    -F panda-${arch}
                cp {{ project-root }}/target/release/libtracer_panda.so \
                    {{ build-dir }}/tracer-panda/panda_madpanda-${arch}.so
                ;;
            *)
                echo unknown or unsupported architecture: "${arch}";
                exit 1
                ;;
        esac
    done

doc:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo doc --no-deps

test:
    #!/usr/bin/env bash
    set -euxo pipefail
    for arch in {aarch64,arm,i386,mips,mipsel,ppc,x86_64}; do
        cargo test --no-default-features -F tracer-panda-bin,panda-${arch}
    done

install:
    #!/usr/bin/env bash
    set -euxo pipefail
    build={{ clean(build-dir / "tracer-panda") }}
    install={{ clean(install-root / install-prefix) }}
    plugins=${install}/lib/panda
    bin=${install}/bin
    mkdir -p ${plugins}/{arm,aarch64,i386,mips,mipsel,ppc,x86_64} -p ${bin}
    for arch in "aarch64" "arm" "i386" "mips" "mipsel" "ppc" "x86_64"; do
        ln -sf ${build}/panda_madpanda-${arch}.so ${plugins}/${arch}/panda_madpanda.so
    done
    for arch in "aarch64" "arm" "i386" "mips" "x86_64"; do
        ln -sf ${build}/panda-trace-${arch} ${bin}/panda-trace-${arch}
    done

clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    install={{ clean(install-root / install-prefix) }}
    plugins=${install}/lib/panda
    bin=${install}/bin
    for arch in "aarch64" "arm" "i386" "mips" "mipsel" "ppc" "x86_64"; do
        rm -rf ${plugins}/${arch}/panda_madpanda.so
    done
    for arch in "aarch64" "arm" "i386" "mips" "x86_64"; do
        rm -rf {{ build-dir }}/tracer-panda/panda-trace-${arch} ${bin}/panda-trace-${arch}
    done
    rm -rf {{ build-dir }}/tracer-panda
    cargo clean --release -p tracer-panda
    cargo clean -p tracer-panda
    
