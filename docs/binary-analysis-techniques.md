# Binary Analysis Techniques

> Technical reference extracted from the [project catalog](binary-analysis-landscape.md) on 2026-11-08. Concepts are relatively stable; individual tool capabilities remain release-dependent. [Evaluation protocol](binary-analysis-evaluation.md).

## Code-analysis implementation matrix

This table is intentionally **not** a feature-score leaderboard. `?` means the implementation has not been traced far enough to make an assertion. “No” is only used for clear product scope. Reader/parser support, disassembler ISA support and decompiler-language support are different dimensions.

| Tool | PE / ELF / MO | Decoder / disassembler | Starting-point discovery | CFG / intermediate representation / decompilation | Names, metadata and signatures |
|---|---|---|---|---|---|
| **binary101** | PE+COFF / ELF / MO structural (depth differs) | **iced-x86 WASM** x86; **LLVM MC-derived WASM** AArch64 | Entry, symbols, callbacks, init arrays, unwind, RTTI, Go/AOT etc. when validated | Reachable-code inspection and control-flow traversal; **no general semantics IR or C decompiler** | Microsoft SDK API enrichment, CLR/R2R/AOT, Go, DWARF, MSVC/Itanium RTTI, LLVM demanglers; **not FLIRT** |
| **Ghidra** | Yes / Yes / Yes | SLEIGH ISA specifications | Layered loader + symbols + patterns + recursive/other analyses | **p-code**; comprehensive analysis, CFG, C-like decompiler | PDB/DWARF, demangling, FID, types, runtime analyzers and scripts |
| **IDA + Hex-Rays** | Yes / Yes / Yes | IDA processor modules | Symbols, relocations, analysis, signatures, user edits | Native analysis and CFG; Hex-Rays **microcode** → structured pseudocode | **FLIRT**, Lumina, type libraries, debug symbols, RTTI, demangling |
| **Binary Ninja** | Yes / Yes / Yes | Architecture-specific plugins / native decoder stack | Symbol and code discovery; user extensibility | **LLIL → MLIL → HLIL**, CFG and structured output | Type libraries, debug info, signatures/plugins; capabilities vary by edition |
| **Rizin** | Yes / Yes / Yes | `librz` architecture plugins; decoder varies by architecture | Analysis commands, symbols, relocations, function heuristics | CFG, **RzIL**; decompiler via supported integrations | Zignatures/signature databases, demangling, plugins |
| **RzWeb** | Whatever bundled Rizin handles | **Rizin** engine in WASM; not an independent decoder | Rizin's analysis, within browser build's constraints | Rizin CFG; decompiler tab depends on included backend (`pdg`/`pdd`/`pdc`, fallback pseudo-disasm) | Rizin facilities/build-dependent |
| **radare2** | Yes / Yes / Yes | radare2 analysis/disassembly plugins | Analysis commands, symbols, patterns | CFG, **ESIL**; decompilers via integrations | `zignatures`, demangling, plugins |
| **Kuna** | ELF/PE etc. via loaders, inspect per release | Rust **SLEIGH** decoder | Derived/extended Ghidra-like loader and function handling | Ghidra-derived decompiler pipeline, p-code family, C-like output | SLEIGH specs and available symbols/prototypes; exact FID coverage not assumed |
| **Pyre** | Yes / Yes / Yes; also WASM modules | C++ Ghidra **SLEIGH** inside Emscripten WASM | Loader/function list + cross-references | **Ghidra p-code and decompiler**; browser code navigation | Lazy Ghidra libc prototypes; broad additional databases not audited |
| **Peek-a-Bin** | **PE**; no general ELF/MO claim | **Capstone WASM**, x86/x64 + AArch64 | Hybrid recursive descent and linear sweep | CFG; **own IR/SSA/struct synthesis decompiler** for x86; optional Ghidra server | PE structures, driver/IOCTL features, signatures; no FLIRT assertion |
| **x86lint** | Raw x86-64 executable code/sections | **Intel XED** linear sweep | Sequential decoding, direct branch-target collection for safety guards | Local peepholes and bounded liveness checks; **not whole-program CFG/decompiler** | No primary FID/RTTI role |
| **armlint** | AArch64 machine code | AArch64 decoder (backend should be checked in source) | Peephole sequences | Local optimization diagnostics; **not decompiler** | No primary FID/RTTI role |
| **elfx86exts** | ELF, MO; other support evolving | **Capstone** | ISA classification from decoded code | Neither semantics IR nor decompiler | CPU-extension report; not FID |
| **Ddisasm** | PE / ELF | Decoder emits candidate instructions; Datalog rules resolve them | Logical evidence from symbols and code/data constraints | **Datalog facts → GTIRB**, CFG and reassemblable assembly; no C decompiler | Symbolization/function boundaries; no FLIRT claim |
| **rev.ng** | PE / ELF / MO | QEMU-based lifting plus LLVM infrastructure | Multi-stage analyses and function detection | **LLVM-oriented IR**, CFG and C decompilation | DWARF/PDB integration in platform; verify tier/release |
| **SalSA Web** | PE-focused | Not a core advertised feature | N/A | Deep PE structure tree, not a C decompiler | File-format records rather than library-function recognition |
| **Checksec Anywhere** | PE / ELF / MO | Targeted fine-grained disassembly for security checks | Not general-purpose code discovery | Security-policy facts; not full CFG/decompilation | Protections, sanitizers, report/SARIF |
| **Detect It Easy** | Broad signatures; PE and more | File scanning, signatures, some static analysis | Entry-point / packer clues | Not primarily a lifting/decompilation engine | **Signature-driven** file/compiler/packer recognition |

**Qualifications.** Ghidra/IDA/Binary Ninja are extensible platforms: “yes” in a format column is not a promise of identical maturity across all subformats and architectures. Pyre's README calls itself **alpha** (primarily x86, AArch64, WebAssembly default specs). Peek-a-Bin's own README distinguishes its x86 decompiler from AArch64 disassembly. A plugin can substantially change an individual installation's abilities.

## Technical pipeline: different questions, different tools

A common mistake is to call all of the following "disassembly". They are substantially different inference problems, with distinct failure modes and mature solutions.

| Stage | Question | Common mechanisms | Representative solutions | Important caveat |
|---|---|---|---|---|
| Container mapping | Which bytes correspond to which VA/RVA, section and loaded segment? | PE sections/directories, ELF `PT_LOAD`, Mach-O segments, relocations, overlays | LIEF, pefile, PortEx, Ghidra loaders, binary101 | A decoded offset is not automatically an executable VA. |
| Candidate start discovery (`seeds`) | Where might executable code begin? | Entry point, exports, symbols, TLS callbacks, init arrays, unwind ranges, debug info, vtables, Go `pclntab`, R2R/AOT metadata | binary101, Ghidra, Rizin, Ddisasm | A seed is **evidence for a starting address**, not guaranteed function extent. |
| Instruction decoding | What instruction does a byte sequence encode? | ISA-specific decoder, opcode/operand tables | **XED**, **iced-x86**, **Capstone**, **LLVM MC**, SLEIGH decode | A valid instruction decode does **not** prove that bytes are code. |
| Code vs data separation | What is actually executable code, and where are function boundaries? | Recursive descent, linear sweep, exception/unwind ranges, relocations, statistical classification, Datalog | Ddisasm, Ghidra, IDA, Rizin, binary101 seed-guided scan | Indirect control flow, jump tables, embedded data, obfuscation remain difficult. |
| CFG and xrefs | Which edges exist between blocks, functions and data? | Direct branches/calls, switch recovery, relocation/symbol evidence, value analysis | Ghidra, Rizin, Binary Ninja, Peek-a-Bin | Full indirect-target recovery is generally not guaranteed. |
| ISA requirements | Which hardware feature predicates occur? | Decoder feature metadata/ISA categorization | elfx86exts (Capstone), binary101 (iced/LLVM), x86lint (XED) | Decoder recognition != guaranteed runnability on a particular CPU. |
| Instruction **semantics** | What does the instruction *do* to registers, memory and flags? | **SLEIGH → p-code**, **RzIL**, **ESIL**, **VEX**, Binary Ninja **LLIL**, LLVM IR after lifting | Ghidra/Kuna/Pyre; Rizin; radare2; angr; Binary Ninja; rev.ng | This is the mapping the earlier discussions referred to: **ISA-to-IR semantic lifting**. A decode library alone is insufficient. |
| Data-flow / SSA | Which definitions reach uses? Which values are constant or dead? | Def-use chains, SSA, abstract interpretation, type constraints, symbolic execution | Binary Ninja MLIL, Ghidra p-code analysis, angr, modern decompilers | Sensitive to incomplete CFG and aliasing. |
| Type and ABI recovery | What are types, call signatures, classes, and layout constraints? | DWARF/PDB, calling convention, type propagation, MSVC/Itanium RTTI, exception metadata | Ghidra, IDA, Binary Ninja, binary101 (metadata/RTTI) | Recovery from runtime structures is different from inference from instructions. |
| Function matching | Is this stripped function `memcpy`/`printf`/a known library routine? | FLIRT signatures, Ghidra FID, Rizin zignatures, library-prototype databases | IDA FLIRT, Ghidra Function ID, Rizin `zignatures`, type libraries | This is **FID/library identification**, not demangling. |
| Demangling | What source-ish name does an encoded symbol represent? | ABI parsers for Itanium, MSVC, Rust, D, etc. | LLVM demanglers, cpp_demangle; binary101 WASM packages | A nice name does not reconstruct an unknown function body or RTTI. |
| Structuring / decompilation | Can CFG and IR become expressions, loops, conditions and C-like code? | SSA simplification, region/loop structuring, types, alias and stack analysis | Ghidra, Kuna, Pyre, Hex-Rays, Binary Ninja HLIL, rev.ng | Decompilation output is a hypothesis, not recovered original source. |
| Binary rewriting / mutation | Can changed code be encoded while preserving layout and semantics? | In-place same-size patch, trampolines, relocation fixups, IR reassembly | Ddisasm + GTIRB, rev.ng, SN4KE | Safe rewriting is considerably harder than flipping a Jcc byte. |

### Decoder vs lifter vs decompiler (quick reference)

| Engine/family | Decoder | Authoritative machine semantics / IR | CFG/dataflow | C-like output | Typical placement |
|---|---|---|---|---|---|
| Intel XED | x86 | Instruction metadata, **not general-purpose lifted IR** | No | No | x86lint; external x86 tooling |
| iced-x86 | x86 | Detailed instruction info; **no full semantic IL** | No intrinsic complete CFG | No | binary101 x86 analysis |
| Capstone | Multi-ISA | Instruction details, **not general-purpose IR** | No | No | Peek-a-Bin decode, elfx86exts |
| LLVM MC | Multi-ISA | Opcode/feature descriptors; **not automatic LLVM IR semantics** | No general CFG | No | binary101 AArch64 decode |
| Ghidra SLEIGH/p-code | Multi-ISA | **p-code** semantic IR | Yes, via Ghidra analyses | Yes | Ghidra, Pyre; Kuna Rust descendant |
| Binary Ninja | Multi-ISA | **LLIL → MLIL → HLIL**, own intermediate levels | Yes | Yes | Binary Ninja |
| Rizin | Multi-ISA | **RzIL** (and other analysis components) | Yes | Via supported decompiler integrations | Rizin, RzWeb |
| radare2 | Multi-ISA | **ESIL** | Yes | Via decompiler integrations | radare2 |
| angr | Multi-ISA | **VEX IR** (primarily) | Yes | Analysis-oriented | angr toolchain |
| rev.ng | Multi-ISA | **QEMU/LLVM-based lifting** | Yes | Yes | rev.ng |
| Ddisasm | Multiple ISAs | **GTIRB structural IR**, not instruction-semantics IL | Yes | No | Reassembly and mutation research |

The term for the “authoritative mapping of assembler to instruction semantics” is generally **instruction semantics specification / semantic lifting**, implemented concretely as `SLEIGH → p-code`, `VEX lifting`, `RzIL`, or another machine-level IR. It is related to but distinct from a decoder's operand metadata. “Authoritative” here means a well-maintained executable specification, **not formally verified perfect semantics**.

### What can supply disassembly seeds?

| Evidence | Examples | Evidence strength | Danger if abused |
|---|---|---|---|
| File-declared code location | PE `AddressOfEntryPoint`, ELF `e_entry`, export addresses | Strong if in mapped executable bytes | An exported RVA may be forwarded/non-code; atypical layouts |
| Loader/runtime callbacks | PE TLS callbacks; ELF `.init_array`, `.fini_array`, dynamic tags | Strong when decoded and range-validated | Wrong relocation/address mode interpretation |
| Symbols and function tables | COFF, ELF symbol tables, PDB/DWARF, Go `pclntab` | Strong under valid metadata contracts | Stale symbols; stripped/partial symbol sets |
| Unwind and exceptions | PE `.pdata`/`xdata`, ELF `.eh_frame`, LSDA | Often strong code-range evidence | Architecture-specific encodings and trampolines |
| Runtime ownership | MSVC/Itanium vtables, NativeAOT eager cctors and module initializers, ReadyToRun function metadata | Strong **when full cross-referenced graph validates** | Pointer-like data and heuristic matches create false positives |
| Discovered direct control-flow targets | Calls, Jcc/Jmp, fallthrough, switch edges | Conditional on correct parent decode | One wrong decode can recursively contaminate analysis |
| Blind prologues/linear sweep | Known byte patterns; alignment guesses | Weak | Embedded data, padding, obfuscated code |

**binary101's recurring design principle:** keep the native file order and original fields visible, decode semantics where evidence permits, validate cross-references, and label unsupported/ambiguous cases rather than forcing an invented “function”. This is a design preference, not proof of accuracy against every competitor.

## Feature-area map: formats, runtimes and resources

| Area | Standard mechanisms and families | Relevant projects | Specific binary101 angle / boundary |
|---|---|---|---|
| PE/COFF | Headers/directories, import/export, TLS, load config, base/dynamic relocations, debug, `.pdata`, resources, Authenticode | PortEx, LIEF, PE Tree, PE-bear, pefile, CFF Explorer, Ghidra | Deep file-oriented view; extra runtime discovery and code seeds; debug and exotic unwind formats vary in completeness |
| ELF | Program/section headers, notes, `.dynamic`, GNU hash, versioning, TLS, relocations, attributes, unwind | LIEF, Ghidra, Rizin, PortEx (PE only), `readelf` | ELF32/64, extended ABI fields, symbol/dynamic relationships, DWARF and AArch64 ISA analysis |
| Mach-O | Fat slices, load commands, dyld linking, signatures, symbols | LIEF, Ghidra, Rizin | Structural analysis; do **not** assume PE-depth parity |
| Debug/source mapping | CodeView, PDB/Portable PDB, DWARF 2–5, CFI, line tables, split DWARF | Ghidra, LLVM tools, LIEF, binary101 | Binary101 decodes many raw metadata structures; full symbolic source reconstruction is a separate problem |
| MSVC C++ ABI | RTTI locator/TypeDescriptor/hierarchies, vftables, EH state machines, MSVC demangling | Ghidra, IDA, PE-bear, binary101 | Relocation-backed validation; confirmed vftable target seeds; layout-restricted |
| Itanium C++ ABI | `_Z...` names, vtables, typeinfo, LSDA, virtual inheritance | Ghidra, LLVM, cpp_demangle, binary101 | Demangling and conservatively confirmed RTTI; distinct from MSVC layout |
| Go | build info, `pcHeader`, `pclntab`, `moduledata`, `_func`, function names | Ghidra scripts, Go tooling, binary101 | Validate internal runtime tables; version-family-dependent; may generate function seeds |
| .NET CLR/R2R/NativeAOT | ECMA-335 metadata, managed resources, ReadyToRun, NativeFormat reflection, AOT initializer arrays | ILSpy, dnSpyEx, Ghidra, binary101 | Rich file-native metadata rendering and selected AOT graph validation; **not** IL decompilation |
| Rust and D | Rust v0/legacy, D symbol demangling; language/runtime-specific metadata | LLVM demanglers, binary101 | Names and detectable metadata, not automatic recovery of original types |
| PE resources | RT_* tree, VERSIONINFO, manifests, dialogs, typelib, MFC/ATL, ribbon, .NET embedded resources | Resource Hacker, CFF Explorer, PE-bear, binary101 | Decode structured resources rather than exclusively hex dump; not every undocumented payload is understood |
| Packed/obfuscated binaries | signatures, entropy, unpacking, memory traces | DIE, Manalyze, PE-sieve, ANY.RUN | File analysis remains static; absence of code findings ≠ absence of packed code |
| Security properties | DEP/NX, ASLR/PIE, RELRO, CFG/CET, Authenticode | Checksec Anywhere, LIEF, binary101 | Explain *recorded* protections, distinguish metadata from actual runtime enforcement |

### Upstream/fork relationships worth remembering

```text
Ghidra (C++ decompiler; SLEIGH + p-code)
├── Pyre: Ghidra C++ decompiler compiled into WASM (Emscripten)
└── Kuna: Rust port/divergent decompiler with SLEIGH; agent-driven development

Rizin
└── RzWeb: Rizin compiled into WASM; browser UI, via rzwasi

Detect It Easy
└── die-in-browser: executes DIE in emulated Linux (v86), NOT a reimplementation

DoD SalSA
└── a-rey/SalSA: browser-oriented PE deep dive

checksec.rs
└── Checksec Anywhere: extended Rust core + WASM + browser UI

GrammaTech Ddisasm → GTIRB → gtirb-rewriting / gtirb-pprinter
└── SN4KE: experimental binary mutation workflow (also rev.ng branch)

Capstone (decoder) → Peek-a-Bin disassembly / elfx86exts ISA detection
Intel XED (decoder) → x86lint instruction-sequence diagnostics
iced-x86 (decoder) → binary101 x86/x64 analysis
LLVM MC (decoder) → binary101 AArch64 analysis
```

**Non-equivalences:** `FLIRT ≠ demangling`; `RTTI ≠ inferred types`; `GTIRB ≠ LLVM IR`; `SLEIGH ≠ CFG itself`; `Capstone/XED/iced decode ≠ function discovery`; `PDB/DWARF ≠ decompiler`; `Go pclntab ≠ conventional linker symbol table`; `GitHub repo created ≠ project created`.
