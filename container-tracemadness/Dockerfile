FROM traceanalysis/dist

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -yq && apt-get install unzip

COPY entrypoint.py /entrypoint
COPY templates/ /usr/local/share/container-tracemadness
ENTRYPOINT ["/entrypoint"]
