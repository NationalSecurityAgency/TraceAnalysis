FROM ubuntu:22.04 AS build-deps

RUN apt-get update -yq && apt-get install --no-install-recommends -y \
    bison build-essential bzr cmake curl file flex g++ git git-lfs graphviz libbfd-dev \
    libclang-dev libglib2.0-dev libsqlite3-dev libssl-dev maven mercurial ninja-build \
    openjdk-21-jdk openssh-client pkg-config python3 python3-pip subversion unzip wget && \
    pip install --upgrade pip

# Taken from: official rust:bullseye (1.80.0)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.80.0
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='3c4114923305f1cd3b96ce3454e9e549ad4aa7c07c03aec73d1a785e98388bed' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='0a6bed6e9f21192a51f83977716466895706059afb880500ff1d0e751ada5237' ;; \
        ppc64el) rustArch='powerpc64le-unknown-linux-gnu'; rustupSha256='079430f58ad4da1d1f4f5f2f0bd321422373213246a93b3ddb53dad627f5aa38' ;; \
        s390x) rustArch='s390x-unknown-linux-gnu'; rustupSha256='e7f89da453c8ce5771c28279d1a01d5e83541d420695c74ec81a7ec5d287c51c' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.27.1/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;

# Taken from: official gradle:jdk17-jammy (8.9)
ENV GRADLE_HOME=/opt/gradle \
    GRADLE_VERSION=8.9
RUN set -o errexit -o nounset \
    && echo "Adding gradle user and group" \
    && groupadd --system --gid 1000 gradle \
    && useradd --system --gid gradle --uid 1000 --shell /bin/bash --create-home gradle \
    && mkdir /home/gradle/.gradle \
    && chown --recursive gradle:gradle /home/gradle \
    && echo "Symlinking root Gradle cache to gradle Gradle cache" \
    && ln --symbolic /home/gradle/.gradle /root/.gradle \
    && echo "Downloading Gradle" \
    && wget https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip \
    && echo "Installing Gradle" \
    && unzip ./gradle-${GRADLE_VERSION}-bin.zip \
    && mv "gradle-${GRADLE_VERSION}" "${GRADLE_HOME}/" \
    && rm ./gradle-${GRADLE_VERSION}-bin.zip \
    && ln --symbolic "${GRADLE_HOME}/bin/gradle" /usr/bin/gradle

# Install arangodb3
ARG ARANGODB3_VERSION=3.11.6-1
ARG ARANGODB3_PASSWORD=root
ADD https://download.arangodb.com/arangodb311/DEBIAN/amd64/arangodb3_${ARANGODB3_VERSION}_amd64.deb /vendor/apt/arangodb3_${ARANGODB3_VERSION}_amd64.deb
RUN bash -c "echo arangodb3 arangodb3/password password ${ARANGODB3_PASSWORD} | debconf-set-selections" && \
    bash -c "echo arangodb3 arangodb3/password_again password ${ARANGODB3_PASSWORD} | debconf-set-selections" && \
    bash -c "echo arangodb3 arangodb3/upgrade boolean false | debconf-set-selections" && \
    apt-get install --no-install-recommends -y /vendor/apt/arangodb3_${ARANGODB3_VERSION}_amd64.deb && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangod.conf && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangosh.conf && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangoimport.conf && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangoexport.conf

# Install PANDA and set env vars
ENV PANDA_PATH=/opt/panda \
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/usr/local/bin
ARG PANDA_VERSION=v1.8.34
ADD https://github.com/panda-re/panda/releases/download/${PANDA_VERSION}/pandare_22.04.deb /vendor/apt/pandare_22.04.deb
RUN set -eux; \
    apt-get install --no-install-recommends -y /vendor/apt/pandare_22.04.deb; \
    mkdir /opt/panda; \
    ln -s /usr/local/share/panda /opt/panda/pc-bios; \
    bash -c 'for arch in {aarch64,arm,i386,mips,mips64,mipsel,ppc,x86_64}; \
    do ln -s /usr/local/lib/panda/${arch} /opt/panda/${arch}-softmmu; \
    ln -s /usr/local/bin/libpanda-${arch}.so /usr/local/lib/panda/${arch}/; \
    ln -s /usr/local/bin/panda-system-${arch} /usr/local/lib/panda/${arch}/; \
    done'

# Install PANDA libosi
ARG PANDA_LIBOSI_VERSION=v0.1.7
RUN set -eux; \
    git clone -b ${PANDA_LIBOSI_VERSION} --depth 1 https://github.com/panda-re/libosi.git /tmp/libosi; \
    mkdir -p /tmp/libosi/build; \
    cd /tmp/libosi/build; \
    cmake -GNinja ..; \
    ninja; \
    ninja package; \
    dpkg -i ./libosi_.deb; \
    cp ./libosi_.deb /vendor/apt/libosi_22.04.deb; \
    rm -rf /tmp/libosi;

# Install Ghidra and set env vars
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_BUILDDATE=20250219
ENV GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILDDATE}.zip && \
    mkdir -p /opt/ghidra && \
    unzip ./ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILDDATE}.zip -d /opt/ghidra/ && \
    rm ./ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILDDATE}.zip

# Install QEMU
ARG QEMU_VERSION=9.0.0
RUN set -eux; \
    wget "https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz"; \
    tar -xJvf ./qemu-${QEMU_VERSION}.tar.xz; \
    mv ./qemu-${QEMU_VERSION} /opt/qemu; \
    rm ./qemu-${QEMU_VERSION}.tar.xz; \
    cd /opt/qemu; \
    ./configure --disable-docs; \
    make -j "$(nproc)"; \
    make install; \
    installdir=`mktemp -d`; \
    make install DESTDIR="${installdir}"; \
    tar -czvf qemu-install.tar.gz -C "${installdir}" .; \
    rm -rf "${installdir}"

# Download Intel PIN
ARG PIN_VERSION=3.30
ARG PIN_KIT=98830
ARG PIN_HASH=g1d7b601b3
ENV PATH=$PATH:/opt/pin
RUN set -eux; \
    pin_name="pin-${PIN_VERSION}-${PIN_KIT}-${PIN_HASH}-gcc-linux"; \
    url="https://software.intel.com/sites/landingpage/pintool/downloads/${pin_name}.tar.gz"; \
    wget "${url}"; \
    tar -xzvf "./${pin_name}.tar.gz"; \
    mv "./${pin_name}" /opt/pin; \
    rm "./${pin_name}.tar.gz"

# Download and build arangodb-java-driver
ARG ARANGODB_JAVA_VERSION=7.3.0
RUN set -eux; \
    git clone --depth 1 --branch v${ARANGODB_JAVA_VERSION} https://github.com/arangodb/arangodb-java-driver.git; \
    cd arangodb-java-driver; \
    mvn -DskipTests -Dmaven.tests.skip=true -Dmaven.javadoc.skip=true package; \
    cp ./shaded/target/arangodb-java-driver-shaded-${ARANGODB_JAVA_VERSION}.jar /usr/share/java/; \
    ln -s arangodb-java-driver-shaded-${ARANGODB_JAVA_VERSION}.jar /usr/share/java/arangodb-java-driver-shaded.jar; \
    cd ..; \
    rm -r arangodb-java-driver

# Download Java JSON parser
ARG JAVA_JSON_DATE=20231013
ADD https://repo1.maven.org/maven2/org/json/json/${JAVA_JSON_DATE}/json-${JAVA_JSON_DATE}.jar \
    /usr/share/java/json-${JAVA_JSON_DATE}.jar

# Install extra rust utilities
RUN cargo install --locked mdbook just

###############################################################################

FROM build-deps as builder

COPY . /opt/traceanalysis
WORKDIR /opt/traceanalysis
RUN just build && just package

###############################################################################

FROM ubuntu:22.04 as dist

RUN apt-get update -yq

# Install arangodb3
ARG ARANGODB3_VERSION=3.11.6-1
ARG ARANGODB3_PASSWORD=root
COPY --from=builder /vendor/apt/arangodb3_${ARANGODB3_VERSION}_amd64.deb /var/cache/apt/archives/arangodb3_${ARANGODB3_VERSION}_amd64.deb
RUN bash -c "echo arangodb3 arangodb3/password password ${ARANGODB3_PASSWORD} | debconf-set-selections" && \
    bash -c "echo arangodb3 arangodb3/password_again password ${ARANGODB3_PASSWORD} | debconf-set-selections" && \
    bash -c "echo arangodb3 arangodb3/upgrade boolean false | debconf-set-selections" && \
    apt-get install --no-install-recommends -y \
        /var/cache/apt/archives/arangodb3_${ARANGODB3_VERSION}_amd64.deb && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangod.conf && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangosh.conf && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangoimport.conf && \
    sed -i '/^authentication = /s/true/false/' /etc/arangodb3/arangoexport.conf

# Install PANDA and set env vars
ENV PANDA_PATH=/opt/panda \
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/usr/local/bin
COPY --from=builder /vendor/apt/pandare_22.04.deb /var/cache/apt/archives/pandare_22.04.deb
RUN set -eux; \
    apt-get install --no-install-recommends -y /var/cache/apt/archives/pandare_22.04.deb; \
    mkdir /opt/panda; \
    ln -s /usr/local/share/panda /opt/panda/pc-bios; \
    bash -c 'for arch in {aarch64,arm,i386,mips,mips64,mipsel,ppc,x86_64}; \
    do ln -s /usr/local/lib/panda/${arch} /opt/panda/${arch}-softmmu; \
    ln -s /usr/local/bin/libpanda-${arch}.so /usr/local/lib/panda/${arch}/; \
    ln -s /usr/local/bin/panda-system-${arch} /usr/local/lib/panda/${arch}/; \
    done'

# Install PANDA libosi
COPY --from=builder /vendor/apt/libosi_22.04.deb /var/cache/apt/archives/libosi_22.04.deb
RUN apt-get install --no-install-recommends -y /var/cache/apt/archives/libosi_22.04.deb

# Install Ghidra and set env vars
ARG GHIDRA_VERSION=11.0
ARG GHIDRA_BUILDDATE=20231222
ENV GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC
COPY --from=builder /opt/ghidra /opt/ghidra
RUN ln -sf ${GHIDRA_INSTALL_DIR}/ghidraRun /usr/local/bin/ghidra

# Install QEMU
COPY --from=builder /opt/qemu/qemu-install.tar.gz /tmp/qemu-install.tar.gz
RUN tar -xzvf /tmp/qemu-install.tar.gz -C / && \
    rm /tmp/qemu-install.tar.gz

# Install Intel PIN
ENV PATH=$PATH:/opt/pin
COPY --from=builder /opt/pin /opt/pin

# Install TraceAnalysis
ENV PIN_PLUGINS=/usr/local/lib/pin \
    QEMU_PLUGINS=/usr/local/lib/qemu
COPY --from=builder /opt/traceanalysis/traceanalysis_0.1-0.deb \
    /tmp/traceanalysis_0.1-0.deb
RUN apt-get update && apt-get install --fix-missing -y /tmp/traceanalysis_0.1-0.deb
