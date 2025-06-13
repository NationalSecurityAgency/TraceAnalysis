FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y curl less emacs unzip
RUN mkdir -p /root/.local/bin
WORKDIR /root/.local/bin
RUN curl -L -O https://github.com/duckdb/duckdb/releases/download/v1.3.0/duckdb_cli-linux-amd64.zip
RUN unzip duckdb_cli-linux-amd64.zip
RUN rm duckdb_cli-linux-amd64.zip
RUN printf 'INSTALL spatial;\n' | ./duckdb 
