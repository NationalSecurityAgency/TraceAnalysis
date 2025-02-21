# TraceAnalysis

## Examples

This folder contains some example programs which have an associated `Dockerfile`
which builds, runs and traces the target program for you. After you've collected
a trace, you can explore it with the `traceanalysis/tracemadness` container (see
`../container-tracemadness` for more information).

## Usage


All of the example containers should follow the same process:

#### Step 1 - Build the Container

```sh
$ docker build -t traceanalysis/example-<name> .
```

First you need to build the docker container. This builds the executable that
will be traced and ensures that the directory structure is set up properly for
the `entrypoint.sh` to trace the example.

#### Step 2 - Create an Output Directory

```sh
$ mkdir -p /tmp/appdata/
```

Next we make an output directory. This is can be wherever you want and is where
all of the results from running the docker container will go.

#### Step 3 - Run the Container

This is where the exciting stuff happens!!!

> NOTE:
>
> For most people, dynamic analysis is not actually that exciting. But you're
> here so you must be pretty cool.

```sh
$ docker run --rm -it \
      -v /tmp/appdata:/app/out \
      <traceanalysis/example-container-name>
```

The above command runs the docker container interactively and mounts the output
directory we specified earlier into the container at `/app/out`. When the
container starts, the `entrypoint` script gets run, which invokes a tracing tool
with the correct arguments to trace the example program.

#### Step 4 - Check the Results

```sh
$ ls /tmp/appdata
exe  maps.out  sysroot  trace.out
```

After the container finishes tracing the example program you should see at a
minimum the above four files. There will most likely be some extra intermediate
files depending on which example you ran but the above four are the important
ones:

| File        | Description                                                                                                                                         |
|:------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| `exe`       | A text file specifying the path to the traced program relative to the `sysroot` directory.                                                          |
| `maps.out`  | A text file with a path to every binary that was dynamically loaded during the trace and the address it was loaded at.                              |
| `sysroot`   | A directory containing all binaries used during execution. All paths in the sysroot folder mirror the binary's path from the root of the container. |
| `trace.out` | A binary file containing the collected trace information.                                                                                           |

## Next Steps

Now that you've collected a dynamic trace of one of the example programs, go
checkout the `container-tracemadness` folder at the root of this repository for
instructions on how to explore the trace data!
