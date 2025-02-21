# TraceAnalysis - Examples

## Multithread

This is meant to be a complete example of tracing a multi-threaded 64-bit X86
program using the QEMU plugin of TraceAnalysis. For more information on the
plugin see `../../tracer-qemu-plugin/`.

## Usage

1. Build:
   ```sh
   ./build.sh
   ```
1. Run:
   ```sh
   mkdir -p /tmp/appdata

   docker run \
     --rm \
     -v /tmp/appdata:/app/out \
     traceanalysis/example-multithread
   ```
