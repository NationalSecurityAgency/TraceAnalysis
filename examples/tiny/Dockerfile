FROM traceanalysis/dist

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential gcc gcc-multilib gdb-multiarch nasm

# Setup the scripts
RUN mkdir -p /app/project
RUN mkdir -p /app/ghidra_scripts
COPY TraceScript.java /app/ghidra_scripts/

# Build the target
COPY target /app/target
WORKDIR /app/target
RUN nasm tiny.s -f elf64 -o tiny.o
RUN ld -o tiny tiny.o

# Run example when container starts up
COPY ./entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
