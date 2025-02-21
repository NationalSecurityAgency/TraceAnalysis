# Examples

A couple of examples are provided in the `examples/` folder to get an idea of how the different tools fit together on a small variety of programs. In this section, we're going to go over an example from start to finish.

## Prerequisties

This probably goes without saying, but make sure you have the `TraceAnalysis` repo pulled down and available on your system. All of the steps below are going to refer to the top project directory called `TraceAnalysis/`, and in order to disambiguate between the directory and the namespaced used for the containers, the directory will be displayed in PascalCase (i.e. `TraceAnalysis/`) while the container namespace will be displayed in lowercase (i.e. `traceanalysis/`).

In order to run these examples, you need to have `docker` or a compatible container runtime (e.g. `podman`) installed. All of our examples are capable of running in non-privileged mode; however, you may need to provide a limited set of capabilities (and thus, require those privileges yourself). At most, the required capabilities are `SYS_PTRACE`, `NET_ADMIN`, and `NET_RAW`.

Each of the example containers builds off of the `traceanalysis/dist` container as a base, so before you begin make sure you build the container at the top of the project (i.e. `TraceAnalysis/Dockerfile`) with the following command:

```bash
docker build --target dist --tag traceanalysis/dist .
```

If you are running in non-privileged mode, you may run into some issues during the install of `arangodb3` as non-privileged containers usually set the limit of the number of files a single process can have open to a value lower than `arangodb3`'s requested amount. This can be solved with the following `--ulimit` argument:

```bash
docker build --ulimit nofile=8192:8192 --target dist --tag traceanalysis/dist .
```

This can take a really long time, so feel free to walk around a bit and grab a coffee. Once you are back and the build is finished, you will have everything you need to get started!

## Simple Example

Each of the examples follows a very similar pattern, build the container, run the container with the output directory mounted, run the `traceanalysis/tracemadness` container with the output from the example to finish injesting the analysis and view the results. We will walk through the `simple` example because it involves the smallest example program which reduces the time it takes to fully analyze.

### Looking Around

So we begin by navigating to the `simple` example:

```bash
cd TraceAnalysis/examples/simple
```

Taking a look around, we have the following layout:

```
.
|-- Dockerfile.pin
|-- Dockerfile.qemu-user
|-- entrypoint-pin.sh
|-- entrypoint-qemu-user.sh
|-- make_sysroot.sh
`-- target
    |-- Makefile
    |-- README.md
    |-- example.c
    `-- input
```

In this directory, we have two `Dockerfile`s, one for `pin` and one for `qemu-user`. `TraceAnalysis` provides a number of different "tracing backends" to fit a variety of ways that a program may need to be traced. For example, if the program you are trying to run is not an `x86(_64)` binary written for Linux or Windows, you will not be able to use `pin` and may need to use a multiarchitecture user space emulator like `qemu-user` or even a full system emulator like `panda`. However, if you are trying to trace a program where you don't control how the program starts up (e.g. an SSH session), `pin` is capable of attaching to a running process while `qemu-user` is not. Our `simple` example does not involve any complicated constraints on execution, so we will just walk through the example with the `pin` backend.

Before we begin, let's take a look at the `simple` example in `target/example.c`:

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct {
  unsigned int id;
  char *name;
  unsigned long hash;
} user_t;

typedef struct {
  user_t *user;
  double score;
} session_t;

typedef struct {
  char type;
  char id;
  char name[15];
  char pw[15];
} init_packet_t;

typedef struct {
  char type;
  char sz;
  char data[30];
} data_packet_t;

double score(char* data, unsigned int sz) {
  double ans = 0.0;
  if(sz > 30) sz = 30;
  for(int i = 0; i < sz; i++) {
    ans += (double)((i % 2 == 0 ? 1 : -1)*data[i])*((double)(1/((double)i+10.0)));
  }
  return ans;
}

unsigned long hash(char* data) {
  unsigned long ans = 0;
  for(int i = 0; i < 15; i++) {
    if(data[i] == 0) break;
    ans += (unsigned long)(i*i*data[i]);
  }
  return ans;
}

session_t *process(char *packet, session_t *current_session) {
  if(packet[0] == 1) {
    init_packet_t *init = (init_packet_t*)packet;
    if(current_session != NULL) {
      if(init->id == current_session->user->id) {
        // user is already in; reset score
        current_session->score = 0.0;
        return current_session;
      }
      // replacing the current user
      free(current_session->user->name);
      free(current_session->user);
      free(current_session);
    }
    current_session = (session_t *)malloc(sizeof(session_t));
    user_t *user = (user_t *)malloc(sizeof(user_t));
    user->id = init->id;
    user->name = (char*)malloc(15);
    for(int i = 0; i < 15; i++) {
      if(init->name[i] == 0) break;
      user->name[i] = init->name[i];
    }
    user->hash = hash(init->pw);
    current_session->user = user;
    current_session->score = 0.0;
  } else if(packet[0] == 2 && current_session != NULL) {
    data_packet_t *p = (data_packet_t *)packet;
    current_session->score += score(p->data, p->sz);
  } else if(packet[0] == 3) {
    if(current_session != NULL) {
      free(current_session->user->name);
      free(current_session->user);
      free(current_session);
    }
    return NULL;
  }
  return current_session;
}

int main(int argc, char** argv) {
  session_t *session = NULL;
  char packet[32];
  char buf[32];
  while(1) {
    int len = read(0, buf, 32);
    if(len < 32) {
      return 1;
    }
    for(int i = 0; i < 32; i++) {
      packet[i] = buf[i];
    }
    session = process(packet, session);
    if(session == NULL) {
      return 0;
    }
    printf("%s (%d): %f\n", session->user->name, session->user->id, session->score);
  }
}
```

As you can see, this is not an overly complicated program, but it has a couple of custom data structures, a custom hash, and a bit of floating point math that all might take a bit of time to understand if we did not have the source code for the program. So let's go ahead and build our container so that we can run the program with the supplied input and see what happens! 

### Taking a Trace

We can build the container with the following:

```bash
docker build --tag traceanalysis/simple-pin-example -f ./Dockerfile.pin .
```

As long as you have built the `traceanalysis/dist` container described in the prerequisites, this build should succeed with no problems! The resulting container will have the built `example` binary and copied a couple of scripts that will run the binary under the `pin` tracing backend. By default, the output of the container is stored in `/app/out`, so we need to make sure that we mount a volume into that location when we run the container. So, without any further ado, let's trace a program:

```bash
docker run --rm -it --volume simple-example-data:/app/out traceanalysis/simple-pin-example
# Example Output:
# [+] Tracing example program...
# Writing trace data to trace.3...
# asda (1): 0.000000
# asda (1): 4.887659
# asda (1): 12.107716
# qweq (2): 0.000000
# qweq (2): -0.378788
# [+] Generating maps.out from memory map information...
# [+] Collecting dynamically loaded libraries into sysroot...
# '/app/target/example' -> 'sysroot//app/target/example'
# '/lib/x86_64-linux-gnu/libc.so.6' -> 'sysroot//lib/x86_64-linux-gnu/libc.so.6'
# '/lib64/ld-linux-x86-64.so.2' -> 'sysroot//lib64/ld-linux-x86-64.so.2'
# [+] Saving <path/to/target> in /app/out/exe...
# [+] Running tm-analyze on trace output...
```

If you are running in non-privileged mode, you may encounter an error resembling: `E: Attach to pid 3 failed: Operation not permitted`. In this case, you should run the container with the following:

```bash
docker run --rm -it --cap-add SYS_PTRACE --volume simple-example-data:/app/out traceanalysis/simple-pin-example
```

In either case, the above command will create a new `docker` volume called `simple-example-data` where all the output is stored. You can checkout what gets stored in this volume by mounting it into another container:

```bash
docker run --rm -it --volume simple-example-data:/data traceanalysis/dist ls -lah /data
# Example Output:
# total 7.3M
# drwxr-xr-x  4 root root 4.0K Aug 30 17:12 .
# dr-xr-xr-x 18 root root 4.0K Aug 30 17:18 ..
# drwxr-xr-x  2 root root 4.0K Aug 30 17:12 analyzed
# -rw-r--r--  1 root root   20 Aug 30 17:12 exe
# -rw-r--r--  1 root root  319 Aug 30 17:12 maps.jsonl
# -rw-r--r--  1 root root  147 Aug 30 17:12 maps.out
# -rw-------  1 root root  121 Aug 30 17:11 pin.log
# -rw-------  1 root root   98 Aug 30 17:12 pintool.log
# drwxr-xr-x  5 root root 4.0K Aug 30 17:12 sysroot
# -rw-r--r--  1 root root 7.3M Aug 30 17:12 trace.out
```

Let's go through a quick explanation of this output:

- `analyzed` - Folder containing analyzed trace information (all of the dynamic data about a trace that gets stored in the database)
- `exe` - Text file containing the path the the executable that was being traced
- `maps.out` - Text file containing a log of each module mapped into the process and their base address
- `sysroot` - Directory containing a minimized `rootfs` with only the executable and the libraries that were mapped during the trace
- `trace.out` - Raw trace file produced by `pin` before analysis
- `pin.log` | `pintool.log` | `maps.jsonl` - Intermediate artifacts retained for debugging

### Exploring Results

At this point, we've got all we need from the example container to start exploring the results in the `traceanalysis/tracemadness` container. So let's go ahead and navigate over to `TraceAnalysis/container-tracemadness`. For the most part, this directory is just a simple container derived from `traceanalysis/dist` and a custom entrypoint. You can build it with:

```base
docker build --tag traceanalysis/tracemadness .
```

The real magic here is in the entrypoint script. We won't go into too much detail here (because the code is still under active development), but we will cover the high-level stages. Assuming the output from the `simple` example is mounted into the right location, `/appdata`, this container will perform the following:

- Create a new Ghidra project called `MyProject` and store it in `/appdata/project`
    - This Ghidra project will contain the contents of `/appdata/sysroot`
    - This Ghidra project will combine the executable and the libraries into a single program
    - This can take a _very_ long time, so it is recommended that you _do not_ delete the project if you want to explore the same trace again
- Extract a couple of static graphs from the combined program and store the results in `/appdata/static`
- Analyze the trace and store the results in `/appdata/analyzed`
- Initialze the database and import all of the dynamic and static data
- Install the TraceMadness extension and open up Ghidra
    - Only happens if the `DISPLAY` environment variable is set

With the exception of the database import (and opening Ghidra), each step _only_ occurs if the output directory for that step is not present. This also means that the step is skipped if you have old results from a previous trace in your volume, so make sure you clean out the volume when you don't want to use the results anymore.

As mentioned, in order to open up Ghidra, you need to have a valid `DISPLAY` variable set in the container. How you forward graphics into your container is a bit environment-specific, but if you are running the container from the same machine that is running your display server (specifically X11), this should be as simple as adding `-v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY` to your `docker run` command. If you are ssh'd into a remote headless server that is running the container, you will have to find a way to forward an X11 session into the container.

When you are ready to roll, run the following command:

```bash
docker run --rm -it --volume simple-example-data:/appdata traceanalysis/tracemadness
```

If you have successfully forwarded your display server into the container, after a rather long analysis period, you should see the Ghidra pop up! Accept the user agreement and open up your project (located at `/appdata/project/MyProject.gpr`), and explore the trace in Ghidra! An in-depth guide for using TraceMadness is under construction and will (hopefully) be coming soon.
