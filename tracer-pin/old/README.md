## WARNING

This tool does not ship with Intel PIN currently. For usage, download Intel PIN 3.27 separately to `pintool/`.

## Usage

Build pintool

```bash
$ pushd pintool && ./build && popd
```

Generate trace

```bash
$ ./pintool/pin-3.27/pin -t ./pintool/trace.so -- /bin/ls
```

Run dataflow[1]

```bash
$ cargo run -- ./trace.out
```

[1] Make sure that specfiles directory is present.

## Limitations

- Currently only supports x86-64
- Currently only supports single threaded
- Dataflow does not function properly for some AVX2 and AVX-512 instructions
