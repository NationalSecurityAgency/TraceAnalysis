# TraceAnalysis

**TraceAnalysis** is a suite of tools for generating, manipulating, analyzing, and exploring program execution traces.

## Building

Currently, **TraceAnalysis** is _only_ supported on Ubuntu 22.04. This does not mean that the tools won't build or work on other distributions/platforms, just that we only test on Ubuntu 22.04. A `Dockerfile` is provided that summarizes the build steps and dependencies. However, provided you have the appropriate toolchains and dependencies in place, you can build any individual tool using the recipes availble in the project's `.justfile`. Each tool has its own `.justfile`, but the types of recipes available are pretty much the same for each tool.

The top-level `.justfile` provides the following recipes:

- `build`
- `test`
- `install`
- `clean`
- `doc`
- `package`

For almost all of these recipes you can provide a target, and `just` will dispatch to the correct recipe for the target (e.g. `just build ghidra-tracemadness` will build `ghidra-tracemadness`). If you do not supply a target (or your target is "all"), the recipe will be run on all targets. As an exception, `package` will package everything in the specified `build-dir`. By default, this directory is `build/` at the root of the project. To change this, simply set the `BUILD_DIR` environment variable. The `package` recipe does not actually build all of the targets, so make sure that you just `just build` to build all of the targets before running `just package`.

## Documentation

Running `just doc` will build all of the documentation for the project. This includes a book-style guide on how to use each of the tools and a walkthrough of the provided examples. The output of this recipe is the `build/docs` folder by default. While this _can_ be viewed locally, many of the links were not designed with that in mind and we recommend that you copy/symlink the output to a folder called "traceanalysis" and run a simple http server above that directory.

```bash
ln -s . build/docs/traceanalysis
python3 -m http.server --directory build/docs/
# Visit http://localhost:8000/traceanalysis/
```

## Acknowledgements

Thank you to the following individuals who (among others) contributed to the initial research and development:

- Luke Mains
- Jean-Paul Miller
- Tod Amon
- Jon Bradley
- Hamilton Link
- Ricardo Alanis
- Nasser Salim

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>
