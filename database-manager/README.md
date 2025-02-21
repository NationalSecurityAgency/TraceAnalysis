# Dataflow Database Helper (`dbmanager`)

A command-line tool for setting up an arangodb instance for use with dataflow
analysis.

## Usage

This tool is mainly used for creating/updating an Arango database instance. To
setup the database for use with `ghidra-tracemadness` use the folowing two
steps:

1. `dbmanager --schema=./data/schema.xml init`
1. `dbmanager --schema=./data/schema.xml populate-all -d /tmp/appdta/out -c ./data/constants/<arch>/`

The first step above will initialize a database at `localhost:8529` with the
default name of `traceanalysis`. Note it uses the schema from the
`traceanalysis` repo. After the database is initialized, the second step is to
load some dynamic trace information into it.

For more informaion on how to use this tool see `dbmanager --help` and
`dbmanger <cmd> --help`.

## Development

TODO

### Testing

Setup docker/podman container:

```sh
$ podman run -d -p 8529:8529 -e ARANGO_NO_AUTH=1 --name dataflowdb arangodb:latest
```
