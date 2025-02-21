project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/docs
    cargo run -p dbmanager --release -- \
      --schema={{ project-root }}/database-manager/data/schema.xml doc md \
      > src/database/schema.md
    cargo run -p dbmanager --release -- \
      --schema={{ project-root }}/database-manager/data/schema.xml doc dot \
      | dot -Tpng -o src/database/schema.png
    mdbook build
    cp -r build {{ build-dir }}/docs/book
    cp -r {{ project-root }}/target/doc {{ build-dir }}/docs/rust
    cp -r {{ project-root }}/strace-spark/docs/build/html {{ build-dir }}/docs/strace-spark
    cp -r {{ project-root }}/tracer-unicorn/docs/build/html {{ build-dir }}/docs/tracer-unicorn
    echo '<meta http-equiv="refresh" content="0; url=book">' > {{ build-dir }}/docs/index.html

clean:
  #!/usr/bin/env bash
  cargo clean --doc
  rm -rf {{ build-dir }}/docs src/database/schema.md src/database/schema.png
  
