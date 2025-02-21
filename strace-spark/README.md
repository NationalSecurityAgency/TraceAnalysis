# `Spark`

A strace output parser written in pure python.

## Overview

This is a python package to convert `strace` output into a structured format,
specifically JSON. `strace` provides a trace of the system calls a program makes
while interacting with the operating system throughout it's lifetime which is a
very useful tool for debugging. Generally, this output is difficult to parse
because of the wide variations it can take. For example, using the `-f` flag
will tell `strace` to follow child processes spawned by the tracee, and will
emit a PID along with each syscall to correlate calls with processes. Another
difficult quirk to deal with is the fact that syscalls can be
interrupted/resumed and trying to track the arguments across lines of `straces`
output text is difficult.

Spark aims to solve these problems and convert `strace` output to a form that is
much easier to work with, namely JSON. Currently, it works quite well! Spark
supports the vanilla strace format, and the multi-process version as well. Spark
is also able to handle unfinished syscalls and saves all arguments which will
get processed once the syscall is complete.

### Sample

<table>
<tr>
<th>Strace Output</th>
<th>JSON</th>
</tr>
<tr>
<td>

```
mmap(
  0x7f4a271e7000,
  69632,
  PROT_READ|PROT_EXEC,
  MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE,
  3,
  0x6000
) = 0x7f4a271e7000









```

</td>
<td>

```json
{
  "id": "c511387f-489f-4263-a970-d7eaac46390c",
  "syscall": "mmap",
  "args": [
    "0x7f4a271e7000",
    "69632",
    "PROT_READ|PROT_EXEC",
    "MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE",
    "3",
    "0x6000"
  ],
  "return_status": 0,
  "pid": null,
  "return_value": "0x7f4a271e7000",
  "error": null,
  "event_type": 2
}
```

</td>
</tr>
<tr>
<td>

```
845497 close(4 <unfinished ...>










845497 <... close resumed>)
    = -1 EBADF (Bad file descriptor)









```

</td>
<td>

```json
{
  "id": "fb34f279-84c5-4a09-b7c9-b1f71e9c73d4",
  "event_type": 3,
  "syscall": "close",
  "args": [],
  "return_status": 3,
  "pid": 845497,
  "return_value": null,
  "error": null
}
{
  "id": "fb34f279-84c5-4a09-b7c9-b1f71e9c73d4",
  "event_type": 3,
  "syscall": "close",
  "args": [
    "4"
  ],
  "return_status": 2,
  "pid": 845497,
  "return_value": "-1",
  "error": "EBADF (Bad file descriptor)"
}
```
</td>
</tr>
</table>

## Installation

**For users:**

```sh
$ git clone <this_repo> spark && cd ./spark/
$ pip install .
```

Alternatively you can use `pipx`:
```sh
$ pipx install .
```

**For developers:**

```sh
$ git clone <this_repo> spark && cd ./spark/
$ pip install -e .[dev]
$ ./scripts/devcheck.sh
```

## Usage

> **NOTE:**
>
> Parsing ability will be improved is strace output is written to a file using
> the `-o` flag. This allows strace to still emit error messages to stderr
> without mucking up the trace data that were trying to parse.

The recommended usage is to send the trace output to a log file (see above note)
and then use spark to parse the trace. Spark will accept either an input file or
using `stdin` but not both.

```sh
$ spark -i <strace.log> -o /dev/null
```

Spark also ascribes to the UNIX philosophy of doing one thing really well and
makes for an excellent pipeline component.

```sh
$ cat <strace.log> | spark | tee /dev/null | awk '{ print $0 }' | jq -cC | less -R
```

#### Complete Example

```sh
$ STRACE_CMD="find /usr/ | awk -F '/' '{ print $2; print $3 }' | sort | uniq"
$ strace -f -qq -v bash -c $STRACE_CMD 2>&1 1>/dev/null \
  | tee strace.log \
  | spark -v 2>spark_errors.log \
  | tee spark.ndjson \
  | less -SF
```


### Arguments:

#### `-i [INPUT_FILE]`

Optional: Input file to read from and convert to structured output. Uses `stdin`
if not present.

#### `-o [OUTPUT_FILE]`

Optional: Output to write structured output to. Uses `stdout` if not present.

#### `-h, --help`

Show help message and exit.

#### `-v, --verbose`

Emit errors and debug messages to `stderr`. More `v's` means more verbose
(Beware...).

## Supported Strace Formatting Options

| Flag        | Description                                                                             |
|:------------|:----------------------------------------------------------------------------------------|
| `-f`        | Trace child processes (follow forks).                                                   |
| `-q`, `-qq` | Suppress informational messages (recommended if not using `-o` flag mentioned above...) |
| `-v`        | Print non-abbreviated versions of environment, stat, termios, etc.  calls.              |
| `-yy`       | Print information associated with file descriptors.                                     |

## Planed Features:
 * `-t`, `-tt`, `-ttt`, `-r` - Timestamp flags
 * `-X verbose` - Named constants and flags

## Building the Documentation Locally

If you don't want to install all of the developer dependencies just to build the
documentation, you can run the following:

```sh
$ python3 -m venv .venv # NOTE: A virtual environment is recommended by sphinx.
$ source .venv/bin/activate

(.venv) $ pip install -e .[docs] # Install dependencies for building documentation.
(.venv) $ cd docs && make html
(.venv) $ cd _build/html/ && python3 -m http.server
```

Then you should be able to browse to `http://localhost:8000` and see the documentation!
