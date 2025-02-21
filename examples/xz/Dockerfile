FROM traceanalysis/dist
VOLUME /app/out

# Install the target + Get test input
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get install -y xz-utils jq
COPY input /app/target/input

# Add Scripts
COPY ./make_sysroot.sh /app/scripts/make_sysroot.sh

# Set starting directory
WORKDIR /app/out

# Run example when container starts up
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
