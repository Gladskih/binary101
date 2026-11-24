# Binary Analysis Techniques

> Technical methods maintained 2026-11-25 (targeted documentation refresh). [Post-build tool catalog](binary-analysis-landscape.md) · [Capability evidence and experimental results](binary-analysis-evaluation.md) · [Compiler/source-to-assembly inventory](compiler-exploration-landscape.md). Concepts are more stable than individual product releases.

## Code-analysis architectures (methods, not status scores)

This matrix compares **technical approaches** (decoding, code discovery, control flow and lifting). The [evaluation matrix](binary-analysis-evaluation.md#compact-capability-comparison-source-described-not-benchmarked) is authoritative for scoped capability-status claims and their evidence. `?` here means insufficient technical inspection. Source descriptions are not executed benchmarks; formats, ISA backends and edition restrictions differ.

| Tool | Formats (selected) | Decoder / disassembler | Starting-point discovery | CFG / intermediate representation / decompilation | Names, metadata and signatures |
|---|---|---|---|---|---|
| [**binary101**](https://github.com/Gladskih/binary101) | PE+COFF / ELF / Mach-O / WebAssembly structural (depth differs) | **iced-x86 WASM** x86; **LLVM MC-derived WASM** AArch64 | Entry, symbols, callbacks, init arrays, unwind, RTTI, Go/AOT etc. when validated | Reachable-code inspection and control-flow traversal; **no general semantics IR or C decompiler** | Microsoft SDK API enrichment, CLR/R2R/AOT, Go, DWARF, MSVC/Itanium RTTI, LLVM demanglers; **not FLIRT** |
| [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) | Yes / Yes / Yes | SLEIGH ISA specifications | Layered loader + symbols + patterns + recursive/other analyses | **p-code**; comprehensive analysis, CFG, C-like decompiler | PDB/DWARF, demangling, FID, types, runtime analyzers and scripts |
| [**IDA + Hex-Rays**](https://hex-rays.com/ida-pro) | Yes / Yes / Yes | IDA processor modules | Symbols, relocations, analysis, signatures, user edits | Native analysis and CFG; Hex-Rays **microcode** → structured pseudocode | **FLIRT**, Lumina, type libraries, debug symbols, RTTI, demangling |
| [**Binary Ninja**](https://binary.ninja/) | Yes / Yes / Yes | Architecture-specific plugins / native decoder stack | Symbol and code discovery; user extensibility | **LLIL → MLIL → HLIL**, CFG and structured output | Type libraries, debug info, signatures/plugins; capabilities vary by edition |
| [**Rizin**](https://github.com/rizinorg/rizin) | Yes / Yes / Yes | `librz` architecture plugins; decoder varies by architecture | Analysis commands, symbols, relocations, function heuristics | CFG, **RzIL**; decompiler via supported integrations | Zignatures/signature databases, demangling, plugins |
| [**RzWeb**](https://github.com/IndAlok/rzweb) | Whatever bundled Rizin handles | **Rizin** engine in WASM; not an independent decoder | Rizin's analysis, within browser build's constraints | Rizin CFG; decompiler tab depends on included backend (`pdg`/`pdd`/`pdc`, fallback pseudo-disasm) | Rizin facilities/build-dependent |
| [**radare2**](https://github.com/radareorg/radare2) | Yes / Yes / Yes | radare2 analysis/disassembly plugins | Analysis commands, symbols, patterns | CFG, **ESIL**; decompilers via integrations | `zignatures`, demangling, plugins |
| [**Kuna**](https://github.com/Noelo-Lab/kuna) | ELF/PE etc. via loaders, inspect per release | Rust **SLEIGH** decoder | Derived/extended Ghidra-like loader and function handling | Ghidra-derived decompiler pipeline, p-code family, C-like output | SLEIGH specs and available symbols/prototypes; exact FID coverage not assumed |
| [**Pyre**](https://github.com/ant4g0nist/pyre) | Yes / Yes / Yes; also WASM modules | C++ Ghidra **SLEIGH** inside Emscripten WASM | Loader/function list + cross-references | **Ghidra p-code and decompiler**; browser code navigation | Lazy Ghidra libc prototypes; broad additional databases not audited |
| [**Peek-a-Bin**](https://github.com/wellingtonlee/peek-a-bin) | **PE**; no general ELF/MO claim | **Capstone WASM**, x86/x64 + AArch64 | Hybrid recursive descent and linear sweep | CFG; **own IR/SSA/struct synthesis decompiler** for x86; optional Ghidra server | PE structures, driver/IOCTL features, signatures; no FLIRT assertion |
| [**PPEE 2.0 preview**](https://www.mzrst.com/puppy/docs/features/data-directories/exception/) | PE only | x86/x64 code scan; decoder implementation not independently audited | `.pdata` and other PE seeds; exact code-seed logic not audited | x64 unwind-aware static diagnostics; exact supported consistency scope is recorded in [Evaluation](binary-analysis-evaluation.md#compact-capability-comparison-source-described-not-benchmarked); not a general C decompiler | PE structures; Go/Rust/.NET/NativeAOT recognizers in product documentation |
| [**Malcat**](https://doc.malcat.fr/) | PE / ELF / MO and numerous other containers | Zydis x86/x64; Capstone ARM/MIPS | Linear/recursive scan, patterns and format metadata | CFG; edition-dependent SLEIGH decompiler | Parsers, ELF Go `pcln`, PE/.NET metadata; see [documented matrix](https://doc.malcat.fr/analysis/filetypes.html) |
| [**binkeep**](https://github.com/kano92-dir/binkeep) | PE / ELF / MO | Capstone WASM: x86/x64/ARM/AArch64 | Linear sweep plus `.pdata`, Mach-O function starts, exports and symbols | xrefs/CFG; **decompiler planned** | PE/.NET, APK/DEX, YARA, imports and signature digests; [guide](https://kano92-dir.github.io/binkeep/guide.html) |
| [**ATLAS**](https://github.com/GreenShoeGarage/Atlas) | PE/ELF parser; MO identification only | Partial x86/x64 and Thumb native decoders | Heuristic/branch-derived probable functions | CFG and developing x86 LIR → pseudocode; incomplete ISA | Firmware/Cortex-M, annotations, local optional debugger; [limits](https://github.com/GreenShoeGarage/Atlas#transparent-v10-limitations) |
| [**KDE ELF Dissector**](https://github.com/KDE/elf-dissector) | ELF | Built-in x86/AArch64 disassembly | ELF structure and symbols; function coverage not audited | Not documented as a general CFG/decompiler | Dependency graph, relocation heatmap, DWARF type layouts, size/loader profiling |
| [**PE Parser (website)**](https://www.peparser.com/en) | PE only | x86/x64 disassembly; .NET IL | Entry, TLS, exports, direct-call traversal | [Bounded integer emulation](https://www.peparser.com/en/blog/stack-strings-floss-decoded-strings) for string recovery with API stubs; CFG/IR and general decompiler unestablished | Go build info/function names, Rust/Nim/Delphi/PyInstaller and CLR metadata (vendor documentation) |
| [**x86lint**](https://github.com/gaul/x86lint) | Raw x86-64 executable code/sections | **Intel XED** linear sweep | Sequential decoding, direct branch-target collection for safety guards | Local peepholes and bounded liveness checks; **not whole-program CFG/decompiler** | No primary FID/RTTI role |
| [**armlint**](https://github.com/gaul/armlint) | AArch64 machine code | AArch64 decoder (backend should be checked in source) | Peephole sequences | Local optimization diagnostics; **not decompiler** | No primary FID/RTTI role |
| [**elfx86exts**](https://github.com/pkgw/elfx86exts) | ELF, MO; other support evolving | **Capstone** | ISA classification from decoded code | Neither semantics IR nor decompiler | CPU-extension report; not FID |
| [**Ddisasm**](https://github.com/GrammaTech/ddisasm) | PE / ELF | Decoder emits candidate instructions; Datalog rules resolve them | Logical evidence from symbols and code/data constraints | **Datalog facts → GTIRB**, CFG and reassemblable assembly; no C decompiler | Symbolization/function boundaries; no FLIRT claim |
| [**rev.ng**](https://github.com/revng/revng) | PE / ELF / MO | QEMU-based lifting plus LLVM infrastructure | Multi-stage analyses and function detection | **LLVM-oriented IR**, CFG and C decompilation | DWARF/PDB integration in platform; verify tier/release |
| [**Reko**](https://github.com/uxmal/reko) | Several executable formats; exact per-loader maturity varies | Architecture-specific decoders | Loader/symbol/disassembly analyses | Binary-to-high-level decompiler; compare against mature RE suites on samples | [Repository](https://github.com/uxmal/reko); not a PE structure-first editor |
| [**RetDec**](https://github.com/avast/retdec) | PE / ELF / MO / COFF / AR / raw | LLVM-based multi-architecture analysis | Disassembly, debug symbols and signatures | CFG, type/class reconstruction and C/Python-like output | [Project README](https://github.com/avast/retdec); **limited maintenance** |
| [**angr**](https://github.com/angr/angr) | Native binary loaders via CLE (architecture/format dependent) | VEX lifting via PyVEX; other backends possible | Static analyses, CFG recovery and symbolic exploration | VEX IR, path/data-flow analyses; not a C decompiler by itself | [Quickstart](https://github.com/angr/angr/blob/master/docs/quickstart.rst) |
| [**CMU BAP**](https://github.com/BinaryAnalysisPlatform/bap) | Executable/object inputs via supported loaders | Binary instruction lifting to BIL | CFG/disassembly passes, plugin analyses | Architecture-neutral IR, microexecution and symbolic tools | [README](https://github.com/BinaryAnalysisPlatform/bap); not primarily a structural PE viewer |
| [**SalSA Web**](https://github.com/a-rey/SalSA) | PE-focused | Not a core advertised feature | N/A | Deep PE structure tree, not a C decompiler | File-format records rather than library-function recognition |
| [**Checksec Anywhere**](https://github.com/trailofbits/checksec-anywhere) | PE / ELF / MO | Targeted fine-grained disassembly for security checks | Not general-purpose code discovery | Security-policy facts; not full CFG/decompilation | Protections, sanitizers, report/SARIF |
| [**Detect It Easy**](https://github.com/horsicq/Detect-It-Easy) | Broad signatures; PE and more | File scanning, signatures, some static analysis | Entry-point / packer clues | Not primarily a lifting/decompilation engine | **Signature-driven** file/compiler/packer recognition |

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
| PE/COFF | Headers/directories, import/export, TLS, load config, base/dynamic relocations, debug, `.pdata`, resources, Authenticode | PPEE, Malcat, PortEx, LIEF, PE Tree, PE-bear, pestudio, PE Explorer, pefile, CFF Explorer, Ghidra | Deep file-oriented view; extra runtime discovery and code seeds; debug and exotic unwind formats vary in completeness |
| ELF | Program/section headers, notes, `.dynamic`, GNU hash, versioning, TLS, relocations, attributes, unwind | KDE ELF Dissector, Malcat, XELFViewer, binsider, LIEF, Ghidra, Rizin, `readelf` | ELF32/64, extended ABI fields, symbol/dynamic relationships, DWARF and AArch64 ISA analysis |
| Mach-O | Fat slices, load commands, dyld linking, signatures, symbols | LIEF, Ghidra, Rizin | Structural analysis; do **not** assume PE-depth parity |
| Debug/source mapping | CodeView, PDB/Portable PDB, DWARF 2–5, CFI, line tables, split DWARF | dwex (DWARF navigation), KDE ELF Dissector (DWARF types), Ghidra, LLVM tools, LIEF, binary101 | Binary101 decodes many raw metadata structures; full symbolic source reconstruction is a separate problem |
| MSVC C++ ABI | RTTI locator/TypeDescriptor/hierarchies, vftables, EH state machines, MSVC demangling | Ghidra, IDA, PE-bear, binary101 | Relocation-backed validation; confirmed vftable target seeds; layout-restricted |
| Itanium C++ ABI | `_Z...` names, vtables, typeinfo, LSDA, virtual inheritance | Ghidra, LLVM, cpp_demangle, binary101 | Demangling and conservatively confirmed RTTI; distinct from MSVC layout |
| Go | build info, `pcHeader`, `pclntab`, `moduledata`, `_func`, function names | PPEE v2 docs, Malcat (pcln/file tables), PE Parser (PE build info/names), Ghidra scripts, Go tooling, binary101 | Validate internal runtime tables; version-family-dependent; may generate function seeds |
| .NET CLR/R2R/NativeAOT | ECMA-335 metadata, managed resources, ReadyToRun, NativeFormat reflection, AOT initializer arrays | PPEE v2 (runtime recognition; exact depth unknown), Malcat (.NET metadata), PE Parser (CLR metadata/IL), ILSpy, dnSpyEx, Ghidra, binary101 | Rich file-native metadata rendering and selected AOT graph validation; **not** IL decompilation |
| Rust and D | Rust v0/legacy, D symbol demangling; language/runtime-specific metadata | LLVM demanglers, binary101 | Names and detectable metadata, not automatic recovery of original types |
| PE resources | RT_* tree, VERSIONINFO, manifests, dialogs, typelib, MFC/ATL, ribbon, .NET embedded resources | Resource Hacker, CFF Explorer, PE-bear, binary101 | Decode structured resources rather than exclusively hex dump; not every undocumented payload is understood |
| Packed/obfuscated binaries | signatures, entropy, unpacking, memory traces | PPEE, Malcat, PE Parser, DIE, Manalyze, PE-sieve, ANY.RUN | File analysis remains static; absence of code findings ≠ absence of packed code |
| Security properties | DEP/NX, ASLR/PIE, RELRO, CFG/CET, Authenticode | Checksec Anywhere, LIEF, binary101 | Explain *recorded* protections, distinguish metadata from actual runtime enforcement |

### Unwind metadata and machine-code consistency: distinct proof obligations

The following are **analysis methods**, not assertions that a named product implements them. Current product evidence and binary101's source-reviewed implementation status live **only** in [Evaluation](binary-analysis-evaluation.md#compact-capability-comparison-source-described-not-benchmarked).

| Validation level | Required input and analysis | What a pass supports | Unresolved by that level |
|---|---|---|---|
| Structural AMD64 unwind metadata | Map `.pdata` ranges and read `UNWIND_INFO` versions/opcodes, chains, offset/flag constraints | Internally consistent **metadata encoding** within supported variants | Agreement with executable instructions |
| AMD64 v1/v2 prologue consistency | Disassemble `[BeginAddress, BeginAddress + SizeOfProlog)`; compare each relevant instruction's effect and **end offset** with `UNWIND_CODE` | Agreement on covered unwind-relevant prologue operations | Body/epilog validity, arbitrary instruction changes |
| AMD64 v3 prologue consistency | Interpret v3 prologue instruction offsets and winding descriptors, including extended prologue size when present; decode actual instructions | Agreement with **v3-specific encoding semantics** | Body/epilog validity; v1/v2 checks cannot be reused mechanically |
| Epilogue consistency | Locate/trace candidate epilogues and validate their instructions against version-specific unwind conventions | The checked exit sequences are unwind-compatible | Whether all reachable execution states or exits were found |
| Full-function unwind-state consistency | Recover reachable CFG, track abstract stack/register/frame state along paths, model calls, dynamic allocations and allowed unwind semantics | Agreement on **modeled and reached** instructions and paths | Indirect/unreached/encrypted code and unsupported effects |
| ELF CFI-to-code consistency | Decode FDE/CIE rules, associate PC ranges with reachable instructions, track CFA/register states and validate call/return and stack effects | Agreement of checked code paths with supported DWARF CFI rules | Correctness of unmodeled instructions or unrelated debug metadata |

A mismatch checker can report a **single top-level finding** with machine-readable reason codes. Preserve the metadata version, exact VA/RVA and bytes, instruction sequence, abstract state, and reason an ambiguity cannot be resolved. An unwind record describes operations needed for unwinding. Validate each claim within the modeled instruction paths, metadata version and supported prologue boundaries.

### Implementation relationships: ports, integrations, dependencies

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

PortEx parser/library
└── PortexAnalyzerGUI: separate desktop view on the parser

Kaitai Struct grammar ecosystem
└── Bytes Revealer: uses grammar-based viewing alongside its own triage features (**integration, not a fork**)

checksec.rs
└── Checksec Anywhere: extended Rust core + WASM + browser UI

GrammaTech Ddisasm → GTIRB → gtirb-rewriting / gtirb-pprinter
└── SN4KE: experimental binary mutation workflow (also rev.ng branch)

Capstone (decoder) → Peek-a-Bin / binkeep disassembly; elfx86exts ISA detection (**shared dependency, not project lineage**)
Zydis + Capstone decoders → Malcat native-code views (with SLEIGH-based decompilation; **dependencies, not forks**)
Intel XED (decoder) → x86lint instruction-sequence diagnostics (**dependency**)
iced-x86 (decoder) → binary101 x86/x64 analysis (**dependency**)
LLVM MC (decoder) → binary101 AArch64 analysis (**dependency**)
```

**Non-equivalences:** `FLIRT ≠ demangling`; `RTTI ≠ inferred types`; `GTIRB ≠ LLVM IR`; `SLEIGH ≠ CFG itself`; `Capstone/XED/iced decode ≠ function discovery`; `PDB/DWARF ≠ decompiler`; `Go pclntab ≠ conventional linker symbol table`; `GitHub repo created ≠ project created`.
