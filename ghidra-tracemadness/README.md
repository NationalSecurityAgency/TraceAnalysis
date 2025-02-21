# TraceMadness

**NOTE:** This tool is under active development. Some features may be non-functional at this time.

## Development

- Follow the instructions from Ghidra for installing the GhidraDev
  plugin into Eclipse
- In Eclipse, create a new Ghidra module project
- Import the contents of the `lib`, `src/main/java/tracemadness`, and `src/main/resources/` directories of this repository into your project
- Add the lib jars to your classpath:
  - Right click your project and select "Properties"
  - Go to "Java Build Path"
  - Select the "Libraries" tab
  - Click "Classpath" in the listing
  - Click the "Add JARs" button to the right
  - Add the two jars from the lib directory:
    - `arangodb-java-driver-shaded-7.3.0.jar`
    - `json-20231013.jar`
  - Click "Apply and Close"

Now you should be able to run the project in debug mode by pressing
F11 and selecting "Ghidra."

### Roadmap

* Functionality/UI tasks:
  * Global issues
    * [DONE] End-to-end example of moderate complexity
    * Possibly modify value display according to program architecture endianness
  * Function trace
    * [DONE] Deduce number of function args to display in the function trace as well as the sources of those arg values (stack or regs and which regs) from the function signature information stored in the Ghidra database rather than inferred from argument usage in function body
  * Instruction trace
    * Make it so that selecting a row in the instruction trace in some way indicates (e.g. with a lighter highlight) the prior instructions that provide the immediate value and addr deps of the selected instruction's side effects
  * Object tracker
    * Refresh code (make sure all buttons at least work)
    * Enable manual propagation of structures on the basis of function returns, instruction run values, etc. (For example, "every time this call to malloc returns, create a struct of the 
    * Give objects lifetimes (so that objects may be declared to exist only between two ticks and future objects may take their place)
  * Refresh syscall tracker
    * Refresh code (rewrite to use the abstract TraceManager listing)
* Integrations
  * Generate Ghidra debugger trace
  * gdb interface
* Research tasks
  * Type inference?
