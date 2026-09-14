# AArch64 ISA analysis

ELF `EM_AARCH64` (183) uses `llvm-aarch64-disasm` 0.1.0, based on LLVM 21.1.8.
The decoder and its WASM load on demand from the application's own assets.
No file bytes leave the browser. Production builds include the package's license
and third-party notices under `vendor/llvm-aarch64-disasm/`.

The analyzer uses the existing ELF seed sources (entry point, functions, constructor
arrays, unwind metadata, NativeAOT metadata) and executable segment/section mappings.
It reads code through the bounded, cached file range reader and follows direct calls,
conditional branches and unconditional branches. Calls also retain the return path;
indirect branches and returns stop a path. Each virtual address is visited once.
Unavailable targets stop a path. Invalid words stop their path; truncated words,
unaligned seeds, malformed ranges, decoder failures and LLVM soft-fail instructions
produce visible notes or invalid-decode counts. Progress yields permit cancellation.

A64 instructions remain little endian regardless of ELF data endianness. ELF32
(ILP32) still contains A64 instructions; the report's bitness describes the ISA,
while ELF class continues to control parsing of metadata.

Requirements group decoded instructions by their complete LLVM opcode predicate
list. `and`, `or`, negation, unknown metadata, and absent feature gates remain
distinct. Arm labels grouping multiple `FEAT_*` names are retained verbatim.
Implied LLVM feature dependencies are not expanded. These are assembler gates,
not a complete CPU compatibility verdict: operand restrictions, HINT aliases,
system registers and execution modes can impose further requirements. Empty gates
do not establish base-ISA validity. Reports retain the LLVM version because its
record identifiers are version-specific.

ELF and PE share the AArch64 requirement table. Each detected predicate group retains
its count and original predicate names in the report data. Descriptions use the bundled
LLVM feature descriptions, preserving grouped Arm labels and Boolean requirements.
The Streaming SVE mode column interprets only explicitly reviewed LLVM 21.1.8 NEON
predicates: ordinary NEON does not guarantee streaming compatibility, streaming-safe
NEON is allowed in either mode, and the SME2.2 variant requires SME2.2 in streaming
mode. Other groups are not classified; no execution-state analysis is performed.

The table starts empty and shows only detected requirement groups. Progress updates
publish independent count snapshots at the decoder's yield intervals; ELF and PE update
the table during processing, retaining the user's sorting. Re-analysis clears the old
rows, and cancellation retains the last displayed sample. Descriptions are available
for every feature in the bundled metadata (318 LLVM feature records in version 0.1.0),
without a curated allowlist. An extension mentioned in an OR or negated gate is not
counted as independently required. Unrecognized future feature IDs have an explicit
description-unavailable fallback rather than an invented explanation.

This is a static sample, with the same limits as the x86 analysis: indirect targets,
embedded data without a distinguishing code path, runtime generation and unpacking
can leave code unseen or cause data to be decoded. `bytesSampled` denotes available
bytes in the selected executable ranges, not bytes copied into memory.

Sources:

- [Arm ELF ABI: header, identification and mapping symbols](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
- [Package API and WASM integration](https://github.com/Gladskih/llvm-aarch64-disasm#readme)
- [LLVM metadata design and limits](https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/docs/metadata.md)
- [Upstream decoder fixtures](https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/test/decode.test.mjs)
