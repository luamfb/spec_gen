## Description

This is a WIP generator of formal specifications for C/C++ programs, which
attempts to extract specifications from source code and/or program execution
traces.
The generated specifications are meant to verify whether the source code
contains memory issues, with particular focus on buffer overflow.

Note that there is no formal guarantee that a program that adheres to the
generated specification will truly be free of memory issues. Instead,
the generated specifications are meant to be reviewed by programmers.
Our intent is to aid in the creation of formal specifications, since altering
the generated ones is likely easier than creating a new specification from
scratch.

## Generation techniques

The system is meant to implement specification generation through several
techniques, including the one presented in
[Ernst et al](https://doi.org/10.1109/32.908957), which generates specifications
through invariants detected in program execution traces.
Instead of relying on code instrumentation to obtain traces, which would require
recompiling the program under analysis, we instead place breakpoints in each
function and observe the execution of the process using the
[`ptrace` system call](https://www.man7.org/linux/man-pages/man2/ptrace.2.html).
The main downside of this method is portability, as it relies on a Linux
system call and requires a small but non-zero amount of architecture-dependent
code. As of now, only x86 is supported, but ARM support is planned as well.
