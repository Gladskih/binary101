# AMD64 prolog reference corpus

These are source-only, local controls. Generated executables, toolchain paths,
inventories and outputs belong in an ignored artifact directory.

- `compiler.cpp`: header-free C++ with fixed and dynamic stack allocation,
  alignment, calls and exception handling. Build for Windows x64 using MSVC and
  clang-cl with `/Od` and `/O2`, and MinGW GCC and Clang with `-O0` and `-O2`.
  Use the installed toolchain's normal runtime libraries and record the complete
  command and version. Stack probes and chained contexts may remain unverified.
- `compiler.go`, `compiler.rs`, `compiler.d`: stack-frame and call controls for
  Go, Rust and DMD. Use Go's default and `-gcflags="all=-N -l"` builds, Rust's
  `-C opt-level=0` and `-C opt-level=3`, and DMD's `-g` and `-O` builds. Select
  Windows x64 explicitly and record toolchain versions alongside the outputs.
- `prologs.s`: LLVM Windows assembly controls for push/allocation, a delayed
  home-area save, an XMM save and frame register, and register-sized allocation.
  Assemble with `clang --target=x86_64-pc-windows-msvc -c prologs.s`, then link with
  `lld-link /dll /noentry /machine:x64 /export:PrologPush /export:PrologHome
  /export:PrologVector /export:PrologRegisterAllocation prologs.obj`.
- `windows-oracle.cpp`: compile with MSVC for x64. Pass the absolute path of the
  generated no-entry DLL and optionally its modeled stack allocation (40 is the
  unchanged control, 56 is the deliberately inconsistent context). The program
  calls Windows `RtlVirtualUnwind` at known instruction boundaries; it does not
  call the assembly functions.
- `windows-state-oracle.cpp`: compile with MSVC `/std:c++17`. This line-oriented
  oracle maps arbitrary PE images with `SEC_IMAGE_NO_EXECUTE` and constructs stack
  and register contexts supplied by the local harness. Its output distinguishes
  successful recovery, disagreement, unmappable inputs and native faults. The
  request parser and limits are documented directly in the source. It does not
  execute image entry points, imports or analyzed instructions.

Check clean controls before interpreting changed cases. Compare the exact asserted
register or stack pointer, not merely an unrelated difference in the context.
Keep inconclusive/faulting cases separate. A synthetic ordinary-entry context is
not evidence that a custom runtime reaches that state in normal execution.
