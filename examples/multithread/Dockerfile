FROM traceanalysis/dist
VOLUME /app/out

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -yq && \
  apt-get install -y build-essential gcc gcc-multilib

# Build the target
COPY ./test-program /app/target
WORKDIR /app/target
RUN make

# Add Scripts
COPY make_sysroot.sh /app/scripts/make_sysroot.sh

# Set starting directory
WORKDIR /app/out

# Run example when container starts up
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
