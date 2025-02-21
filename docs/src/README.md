# TraceAnalysis introduction

TraceAnalysis is a suite of tools designed to help a reverse engineer
in a specific situation: Given a **system of interest** and a
**behaviour exhibited by the system in actual execution**,
TraceAnalysis provides a way to more quickly understand the
implementation details of the program that underlie that specific
observed behaviour.

For a simple example, a reverse-engineer is examining a
number-guessing game. They are interested in how the "random" target
numbers are generated. So they play through the game and make a
guess. At that point, the program will have generated its secret
number and compared it to the user's input, ergo there is a dataflow
path from something the reverse-engineer should be able to understand
easily (their guess being received) to the thing they are interested
in (the process of generating the secret number). TraceAnalysis is
designed to help find and follow paths of this kind.

In general, Reverse engineering is a process of learning about the
system under study. Learning involves connecting new information to
already-known information. TraceAnalysis enables a process wherein a
reverse-engineer may turn initial understanding (such as about
external interfaces, system calls, protocols, and APIs) into deep
system understanding (such as about state machines, structures, and
the like).

* **Identifying already-known information:** When approaching a new
  system, there are often things already understood. For a few
  examples:

  * **Communication data**: If the system communicates externally, we
    might know the format of the input and/or output files, packets,
    etc. and so understand the meaning of the bytes.

  * **APIs**: If it performs library or system calls, we might have
    some understanding of the meaning of the arguments to those based
    on our knowledge of the relevant APIs.

  * **Symbols**: Some programs come with symbols that might help to
    understand, at some level, what a particular variable or function
    means in the context of the larger system

* **Connecting known information to unknown information:** The basic
  tool for expanding from this nascent understanding to a fuller
  understanding of the system as it runs is that of following the
  flows of data, precisely understood. 

* **Organizing learned understanding:** The basic tool for capturing
    what we learn about the program is in **typed objects** which
    describe the structure of memory regions as they are manipulated
    at runtime. But these objects are manipulated by code, and thus we
    can understand not just the structures of memory at runtime, but
    the structures that the code was written to manipulate.

The workflow that enables this in practice is:

* Employ a trace collection method to capture **trace file**: a
  detailed execution trace of the system as it exhibits the behaviour
  of interest.

  Collection tools are as varied as types of systems, and many examples are
  found in the `tracer-*` folders. Tools for adjusting and simplifying
  collected traces are installed as binaries named `tm-*`.

* Run the provided **static+dynamic analysis tool** on the trace file
  to generate an **enriched trace database** and a **ghidra project.**

  Details about the analyses can be found in `docs/src/dataflow.md` 
  
* Open the **ghidra project** in Ghidra with the TraceMandess plugin
  installed and use it to explore the trace and get answers to your
  questions.
