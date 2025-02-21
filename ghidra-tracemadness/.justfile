project-root := env("TRACEANALYSIS_SRC", parent_dir(justfile_dir()))
build-dir := env("BUILD_DIR", project-root / "build")
install-root := env("INSTALL_ROOT", "/")
install-prefix := env("INSTALL_PREFIX", "usr/local")

ghidra-version := env("GHIDRA_VERSION", "11.0")
ghidra-install-dir := env("GHIDRA_INSTALL_DIR", '/opt/ghidra/ghidra_' + ghidra-version + '_PUBLIC')
arangodb-java-version := env("ARANGODB_JAVA_VERSION", "7.3.0")
java-json-version := env("JAVA_JSON_VERSION", "20231013")

print:
    echo {{ build-dir }}

build:
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir -p {{ build-dir }}/ghidra-tracemadness/scripts
    cp /usr/share/java/arangodb-java-driver-shaded-{{ arangodb-java-version }}.jar lib/
    cp /usr/share/java/json-{{ java-json-version }}.jar lib/
    gradle -PGHIDRA_INSTALL_DIR={{ ghidra-install-dir }}
    cp dist/ghidra_{{ ghidra-version }}_PUBLIC_$(date +%Y%m%d)_ghidra-tracemadness.zip \
        {{ build-dir }}/ghidra-tracemadness/ghidra_{{ ghidra-version }}_PUBLIC_$(date +%Y%m%d)_tracemadness.zip
    cp ghidra_scripts/* {{ build-dir }}/ghidra-tracemadness/scripts/

doc:

test:

install:
    #!/usr/bin/env bash
    set -exuo pipefail
    install={{ clean( install-root / install-prefix / "share/tracemadness" ) }}
    extensions={{ clean( install-root / ghidra-install-dir / "Extensions/Ghidra" ) }}
    mkdir -p ${install}
    cp {{ build-dir }}/ghidra-tracemadness/*tracemadness*.zip ${install}/
    ln -sf {{ build-dir }}/ghidra-tracemadness/scripts ${install}/scripts
    if [ -d ${extensions} ]; then
        cp {{ build-dir }}/ghidra-tracemadness/*tracemadness*.zip ${extensions}/
    fi

clean:
    #!/usr/bin/env bash
    set -exuo pipefail
    install={{ clean( install-root / install-prefix / "share/tracemadness" ) }}
    extensions={{ clean( install-root / ghidra-install-dir / "Extensions/Ghidra" ) }}
    rm -rf ${install} {{ build-dir }}/ghidra-tracemadness .gradle/ build/ dist/ lib/*.jar \
        ${extensions}/*tracemadness*.zip
