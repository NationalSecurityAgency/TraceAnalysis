FROM traceanalysis/dist
VOLUME /app/out

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential g++ iproute2 tcpdump xsltproc tshark jq

# Build Dropbear
WORKDIR /app/target
ADD https://matt.ucc.asn.au/dropbear/releases/dropbear-2022.83.tar.bz2 /app/target/dropbear.tar.bz2
RUN tar -xjvf dropbear.tar.bz2
WORKDIR /app/target/dropbear-2022.83
RUN sed -i -e '/DROPBEAR_REEXEC/s/1/0/' default_options.h
RUN sed -i -e '/DROPBEAR_NOFORK/s/0/1/' debug.h
RUN ./configure --disable-zlib --enable-bundled-libtom && make

# Generate SSH Keys
RUN mkdir /root/.ssh
RUN ./dropbearkey -t rsa -s 1024 -f /app/target/host_rsa
RUN ./dropbearkey -t rsa -s 1024 -f /app/target/id_rsa
RUN ./dropbearkey -f /app/target/id_rsa -y | sed -n 2p >> /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys

# Add Scripts
COPY scripts /app/scripts

# Set starting directory
WORKDIR /app/out

# Run example when container starts up
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
