# TraceMadness

**NOTE:** Please refer to the [examples document](docs/src/examples.md) for a
more in depth overview of building and using this container.

## Building

Make sure you have built the `traceanalysis/dist` container at the root of this
project. You should just need to run `docker build -t traceanalysis/tracemadness .` after that.

## Running

1. Set up a directory (we will call it `$TM_DATA`) with the following data (the
   example container will set one of these up for you):

|                          |                                                                                                                                                                                       |
|:-------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`$TM_DATA/trace.out`** | A trace file                                                                                                                                                                          |
| **`$TM_DATA/maps.out`**  | A memory map of the address space of the process that was traced, with lines formatted as `/path/to/lib 0xSTART_ADDRESS 0xEND_ADDRESS`                                                |
| **`$TM_DATA/sysroot`**   | A sysroot directory for the program that contains each of the files referenced in the memory map (so all paths in the memory map will resolve when taken as relative to this sysroot) |
| **`$TM_DATA/exe`**       | A text file that contains the path to the executable within the sysroot (e.g. `/usr/bin/the_program`)                                                                                 |

2. To start the container and dataflow's enrichment process, run the following
   code block and wait a while for the trace to be enriched and indexed in the
   database.

   ```sh
   export TM_DATA=/tmp/appdata
   docker run \
   --rm -it \
   -v /tmp/.X11-unix:/tmp/.X11-unix \
   -v $TM_DATA:/appdata traceanalysis/tracemadness \
   /entrypoint.sh
   ```

3. Run Ghidra inside the container and configure the TraceMadness plugin:

   1. Inside the container, run `DISPLAY=:0
   /opt/ghidra/ghidra_11.0_PUBLIC/ghidraRun`. This makes assumptions about your
   X11 setup. See the prerequisites section below for some notes.

   2. Accept the Ghidra User Agreement

   3. Open the auto-created project in `/opt/ghidra/projects/MyProject.gpr`

   4. Navigate the project to the original binary within the sysroot and
      double-click it.

   5. Ghidra will ask if you want to configure new plugins. Say "Yes" and select
   the box next to TraceMadness on the window that appears (the box may take a
   moment to select as a network connection is made to the database at this
   point).

   6. In the CodeBrowser tool, go to `Window > MadnessPlugin` to open the
      TraceMadness extension and begin exploring!

**Prerequisites:**

- For the purposes of running Ghidra's UI inside the container, this approach
  supposes your X11 connection is via Unix domain socket in `/tmp/.X11-unix`. If
  you are connecting over ssh, you can forward it over Unix domain socket with
  e.g. `ssh -NfT -R /tmp/.X11-unix/X0:/tmp/.X11-unix/X100 remote.host` where
  `X0` will thus be the remote host's `DISPLAY` and where `/tmp/.X11-unix/X100`
  is here assumped to be the local X11 UDS.

## Running the example

Collect the trace data:

```
pushd ../examples/simple-qemu-user
mkdir /tmp/appdata
./build.sh
docker run \
  --rm -it \
  -v /tmp/appdata:/app/out \
  traceanalysis/example-simple-qemu-user
popd
```

Run TraceMadness with the trace data:

```
./build.sh
docker run \
  --rm -it \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v /tmp/appdata:/appdata traceanalysis:tracemadness \
  /entrypoint.sh
```

and then follow the steps above from step 3 onward.
