# TraceAnalysis - Examples

## Dropbear

This example traces the dropbear SSH server implementation.

## Usage

1. Run:
   ```sh
   mkdir -p /tmp/appdata

   docker run \
     --rm \
     -v /tmp/appdata:/app/out \
     traceanalysis/example-dropbear
   ```

For an extra challenge, you can run the example with the binary stripped.

```sh
docker run --rm -v /tmp/appdata:/app/out traceanalysis/example-dropbear --stripped
```
