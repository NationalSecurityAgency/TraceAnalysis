# TracePintool

A pintool for use with Intel PIN to instrument a program and output
a trace in the new trace format for dataflow.

## Dependencies

Compiling this program requires a version of `Pin` to be in the same directory.

### Getting Pin

Grab whichever Pin kit you would like from [Intel's download page](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html).


## Building

See `build.sh`

> NOTE:
>
> Build will make a 32 and 64-bit version of the pintool. It uses the `$PIN_ROOT` environment variable
> which defaults to `./pin`. It is recommended to symlink `./pin` to the version of the pin kit you
> downloaded in the previous step.

## Running

```bash
$PIN_ROOT/pin -t obj-intel64/pintool.so -o trace.out -- /bin/ls
```

## Debugging

Follow the insructions for debugging a pin tool in the relevant pin docs for pin version. The steps below are
meant to be a simple example for those who don't want to read documentation. **Make sure to rebuild the pintool
with `DEBUG=1` or use `./debug_build.sh`!**

1. In one terminal window, setup gdb:

   ```
   $ gdb $PIN_ROOT/intel64/bin/pinbin
   ```
2. In another terminal run `pin`, telling it to pause before executing so we can attach to it with gdb:
   ```
   $ $PIN_ROOT/pin -pause_tool 20 -t ./obj-intel64/pintool.so -- /bin/ls
   Pausing for 20 seconds to attach to process with pid 2378997
   To load the debug info to gdb use:
   *****************************************************************
   set sysroot /not/existing/dir
   file
   add-symbol-file </full/path/to/obj-intel64/pintool.so> <0x##> -s .data <0x##> -s .bss <0x##>
   *****************************************************************
   ```
3. Quickly back in the terminal with gdb running, attach to the `pinbin` process.
   ```
   (gdb) attach 2378997
   Attaching to program: /.../.../.../intel64/bin/pinbin, process 2378997
   (gdb) Reading symbols from /lib64/ld-linux-x86-64.so.2...
   Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
   0x00007fced04af983 in ?? ()
   (gdb)
   ```
4. Load `pintool.so` into gdb at the correct address, so gdb can find your symbols and set breakpoints
   on named functions. You should copy the `add-symbol-file` line from the output of pin in the second
   terminal.
   ```
   (gdb) add-symbol-file </full/path/to/obj-intel64/pintool.so> <0x##> -s .data <0x##> -s .bss <0x##>
   add symbol table from file "/full/path/to/obj-intel64/pintool.so" at
    .text_addr = 0x7fced02343a0
    .data_addr = 0x7fced03b39c0
    .bss_addr = 0x7fced03b43c0
   Reading symbols from /full/path/to/obj-intel64/pintool.so...
   (gdb)
   ```
5. Set a breakpoint and `cont`. Happy hacking!
