# Binary Analysis Landscape: Tools, Engines, and Alternatives

> Research snapshot: **2026-10-24**. A companion to [binary101](https://github.com/Gladskih/binary101), **not** a ranking or a feature-coverage claim.
>
> Scope: projects investigated in earlier binary101-related discussions, plus the principal reusable engines behind them. This is a curated, technically-oriented survey; absence from a cell means **not established by this survey**, not proof that a feature does not exist.

## Reading this report

**Dates.** `Created` means **GitHub repository creation**, not first public release or project inception. `Last push` is GitHub's `pushed_at` (not `updated_at`; documentation edits, mirrors and bots may count). Both were checked on 2026-10-24, mostly against the GitHub API. `Active` = pushed within approximately 90 days; `Quiet` = more than 90 days; `Dormant` = more than a year; `Archived` = marked archived. These are **repository activity indicators**, not product-lifecycle guarantees. The large commercial projects have separate release calendars.

**Ownership.** `Owner` is the repository namespace, **not necessarily the sole developer, original author, legal owner or current maintainer**. Known lead people or institutional origin appear in notes when substantiated.

**Money.** `Unverified` means that this survey found **no verified revenue/funding model**; it emphatically does *not* mean unfunded, volunteer-only or unprofitable. `Sponsor` indicates explicitly acknowledged financial/institutional support; `Commercial` indicates a sold product/service, not known revenue. OSS licenses are *not* business models. A GitHub star count is not a quality or funding measure. See [Funding and incentives](#funding-and-incentives).

**Abbreviations.** `PE` = Portable Executable; `ELF` = Executable and Linkable Format; `MO` = Mach-O; `RE` = reverse engineering; `CF` = control flow; `CFG` = control-flow graph; `IR` = intermediate representation; `RTTI` = runtime type information; `FID` = function identification; `R2R` = ReadyToRun; `AOT` = ahead-of-time compilation; `?` = unknown/unchecked; `—` = not central to the product, *not* evidence of absence.

## 1. Browser-based analyzers and adjacent projects

| Project | Scope and distinguishing idea | Owner / maintainer context | Created | Last push | Status | Business / funding |
|---|---|---|---|---|---|---|
| [**binary101**](https://github.com/Gladskih/binary101) | Local, file-oriented structural and semantic inspection; deep PE/ELF work | `Gladskih` | 2025-11-10 | 2026-10-24 | Active | Personal OSS; no published revenue claim |
| [**Kuna**](https://github.com/Noelo-Lab/kuna) | Rust port/evolution of Ghidra decompiler, agent-oriented; browser/CLI/Ghidra | `Noelo-Lab`; lead **Zion Basque** | 2026-06-07 | 2026-10-24 | Active | **Sponsor**: AFRL, Metalware, DoD explicitly thanked |
| [**Pyre**](https://github.com/ant4g0nist/pyre) | Real Ghidra C++ decompiler in WebAssembly, SLEIGH specs loaded on demand | `ant4g0nist` | 2026-05-04 | 2026-05-04 | Quiet; alpha | Unverified |
| [**Peek-a-Bin**](https://github.com/wellingtonlee/peek-a-bin) · [demo](https://wellingtonlee.github.io/peek-a-bin/) | Browser PE disassembler, xrefs, CFG, own SSA/IR decompiler, annotations | `wellingtonlee` | 2026-02-13 | 2026-10-08 | Active | Unverified |
| [**RzWeb**](https://github.com/IndAlok/rzweb) · [demo](https://rizin.pages.dev/) | Complete Rizin environment compiled to WASM | `IndAlok`; depends on Rizin and `rzwasi` | 2026-01-15 | 2026-10-24 | Active | Unverified |
| [**SalSA Web**](https://github.com/a-rey/SalSA) · [demo](https://a-rey.github.io/SalSA/) | Browser deep-dive PE parser, derived from DoD SalSA | `a-rey`; upstream `deptofdefense/SalSA` | 2019-05-30 | 2020-05-08 | Dormant | Unverified |
| [**Checksec Anywhere**](https://github.com/trailofbits/checksec-anywhere) · [demo](https://checksec-anywhere.com/) | In-browser PE/ELF/MO security-feature checks, bulk reports, SARIF | `trailofbits` | 2025-06-02 | 2026-10-20 | Active | Company OSS; Trail of Bits offers security consulting; **not evidence of product revenue** |
| [**die-in-browser**](https://github.com/xoreaxlmbdx/die-in-browser) | Full Detect It Easy inside Linux-on-v86 browser emulator | `xoreaxlmbdx` | 2025-12-28 | 2026-07-23 | Quiet (93 days) | Unverified |
| [**Infectio**](https://github.com/filippofinke/infectio) · [demo](https://infectio.filippofinke.ch/) | Rust/WASM local malware triage across binaries, documents and archives; optional local LLM | `filippofinke` | 2025-10-12 | 2025-10-12 | Dormant | Unverified |
| [**PeNet**](https://github.com/secana/PeNet) | .NET PE parsing library; web front-end discussed separately | `secana` | 2015-07-02 | 2026-10-15 | Active | Unverified |
| [**Online Cyber Tools PE Analyzer**](https://onlinecybertools.com/tools/reverse-engineering/pe-analyzer) | Online PE headers, imports/exports, disassembly, strings and anomaly inspection | Owner not established | ? | N/A | Website; lifecycle unverified | Unverified |
| [**Binary Triage**](https://qbitz.foo/binary-triage/index.html) | Browser PE triage, entropy, signatures and suspicious indicators | Owner/repository not established | ? | N/A | Website; lifecycle unverified | Unverified |
| [**Dogbolt**](https://dogbolt.org/) | Compare outputs of multiple decompilers, usually via hosted backends | Public-service operators; maintainer not checked | ? | N/A | Service availability not audited | Unverified |
| [**Binary Ninja**](https://binary.ninja/) | Professional RE product; desktop and browser-accessible options | **Vector 35** | Product predates this survey | API repo 2026-10-23 | Active product/API | **Commercial** software licenses |
| [**Binocular**](https://hunterworks.software/binocular/) | Binary inspection and comparison; previously discussed as structural diff alternative | Owner/repository not checked | ? | N/A | Unverified | Unverified |

**Important architectural distinction:** local browser parsing does not make products equivalent. `RzWeb` runs a comprehensive native RE engine in WASM; `Pyre` ports a C++ decompiler; `Kuna` ships a Rust decompiler core; `die-in-browser` boots a miniature guest OS; `binary101` is deliberately a file-structure-first inspector with independent semantic analyses.

## 2. Desktop suites, format parsers, malware tools

| Project | Primary role | Owner / stewardship | Created | Last push | Status | Economics |
|---|---|---|---|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Full RE suite: disassembly, SLEIGH/p-code, analysis, decompilation | US **NSA** | 2019-03-01 | 2026-10-22 | Active | Government-developed OSS; not a paid license product |
| [IDA + Hex-Rays](https://hex-rays.com/ida-pro) | Professional RE/disassembly/decompilation | **Hex-Rays** | N/A | N/A | Commercial product | **Commercial** licenses |
| [Binary Ninja API](https://github.com/Vector35/binaryninja-api) | Public API and extensions for the Binary Ninja product | **Vector 35** | 2015-10-30 | 2026-10-23 | Active | **Commercial** main product |
| [Rizin](https://github.com/rizinorg/rizin) | Open RE framework, RzIL, analysis, patching | `rizinorg` community | 2020-09-30 | 2026-10-24 | Active | OSS; funding not established |
| [radare2](https://github.com/radareorg/radare2) | CLI-oriented RE framework, ESIL | `radareorg` community | 2012-07-03 | 2026-10-24 | Active | OSS; funding not established |
| [Cutter](https://github.com/rizinorg/cutter) | GUI for Rizin | `rizinorg` | 2017-09-25 | 2026-09-11 | Active | OSS; funding not established |
| [LIEF](https://github.com/lief-project/LIEF) | PE/ELF/MO parser/editor/instrumentation library (C++/Python/Rust) | `lief-project` | 2017-03-16 | 2026-10-22 | Active | OSS; financial model not established |
| [PortEx](https://github.com/struppigel/PortEx) | Deep Java PE parser resilient to malformed samples | `struppigel` | 2013-09-27 | 2026-10-21 | Active | Unverified |
| [PE Tree](https://github.com/blackberry/pe_tree) | PE structure tree based on `pefile` and PyQt5 | `blackberry` | 2020-07-27 | 2022-07-09 | **Archived** | Company-published OSS, no project-specific revenue claim |
| [PE-bear](https://github.com/hasherezade/pe-bear) | Detailed PE GUI inspection | `hasherezade` | 2022-09-18 | 2026-10-14 | Active | Unverified |
| [pefile](https://github.com/erocarrera/pefile) | Python PE library | `erocarrera` | 2015-04-13 | 2026-10-12 | Active | Unverified |
| [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) | Packers, compilers, file-type signatures and static inspection | `horsicq` | 2014-06-01 | 2026-10-24 | Active | Unverified |
| [Manalyze](https://github.com/JusticeRage/Manalyze) | PE malware triage and rule-driven suspiciousness | `JusticeRage` | 2015-08-16 | 2026-08-29 | Active | Unverified |
| [PE-sieve](https://github.com/hasherezade/pe-sieve) | Detect injected/replaced/modified PE *in live processes* | `hasherezade` | 2017-08-22 | 2026-06-06 | Active | Unverified |
| [CFF Explorer](https://ntcore.com/explorer-suite/) | Windows GUI PE editor and inspector | **NTCore** | ? | N/A | Release activity not checked | Unverified |
| [PE Tools](https://petoolse.github.io/petools/) | PE inspection, dump/rebuild, comparison | Project stewardship not verified | ? | N/A | Unverified | Unverified |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Embedded files/firmware structures and extraction | `ReFirmLabs` | 2013-11-15 | 2026-08-11 | Active | Corporate OSS; direct project revenue unverified |
| [CyberChef](https://gchq.github.io/CyberChef/) | General transformations of binary/text data | GCHQ-originated OSS | ? | N/A | Not audited | Government-originated OSS |
| [ANY.RUN](https://any.run/) | Hosted interactive malware sandbox | ANY.RUN | N/A | N/A | Product | **Commercial** SaaS |
| [VirusTotal](https://www.virustotal.com/) | Hosted sample reputation/multiscanner, not a local structural parser | Google/Chronicle | N/A | N/A | Product/service | Commercial/enterprise offerings |

`pe-bear` has an older project history than the current GitHub repository's 2022 creation date. **Do not confuse repo dates with invention dates.**

## 3. ISA analytics, semantic diagnostics and binary rewriting

| Project | Principal method | Owner | Created | Last push | Status | Economics |
|---|---|---|---|---|---|---|
| [x86lint](https://github.com/gaul/x86lint) | XED decode, linear sweep, peephole checks with local soundness/liveness guards | `gaul` | **2018-11-08** | 2026-09-27 | Active | Unverified |
| [armlint](https://github.com/gaul/armlint) | AArch64 machine-code optimization checks; sibling of x86lint | `gaul` | 2026-05-23 | 2026-10-23 | Active | Unverified |
| [elfx86exts](https://github.com/pkgw/elfx86exts) | Capstone-based detection of ISA extensions from binary code | `pkgw` | 2017-09-29 | 2026-10-22 | Active | Unverified |
| [Ddisasm](https://github.com/GrammaTech/ddisasm) | Multi-pass disassembly: Datalog/Soufflé facts → **GTIRB** → reassemblable assembly | `GrammaTech` | 2018-09-13 | 2026-10-13 | Active | Corporate research OSS; project economics not established |
| [rev.ng](https://github.com/revng/revng) | QEMU/LLVM-based binary lifting, analysis and C decompilation | `revng` / rev.ng Labs | 2016-12-15 | 2026-10-22 | Active | Open core; commercial/private/offline offerings described on [pricing](https://rev.ng/pricing) (availability/prices must be rechecked) |
| [SN4KE](https://github.com/pwnslinger/sn4ke) | Binary mutation research on Ddisasm/GTIRB and rev.ng engines | `pwnslinger`; 2021 research by Ahmadi, Kiaei, Emamdoost | 2020-07-10 | 2022-11-21 | **Dormant** | Academic research; no verified commercial model |
| [Mull](https://github.com/mull-project/mull) | Mutation testing for C/C++ based on **LLVM IR**, not generic post-build patching | `mull-project` | 2016-05-15 | 2026-10-20 | Active | OSS, package hosting sponsored by Cloudsmith; revenue unverified |
| [BinDiff](https://github.com/google/bindiff) | Cross-binary function matching/diff from code and CFG features | `google` | 2023-09-20 | 2026-09-18 | Active | Historical commercial product lineage; present OSS GitHub edition |
| [Diaphora](https://github.com/joxeankoret/diaphora) | Function-level diff, IDA integration, program similarity | `joxeankoret` | 2015-03-20 | 2026-10-20 | Active | Unverified |
| [Ghidra Version Tracking](https://ghidra-sre.org/) | Pair functions/data across versions | NSA/Ghidra | Included with Ghidra | — | Active parent | Government OSS |
| [VBinDiff](https://www.cjmweb.net/vbindiff/) | Byte-level hex differencing | Historical independent tool | ? | N/A | Unverified | Unverified |
| [Bloaty](https://github.com/google/bloaty) | Binary *size attribution*, not decompilation | `google` | 2016-11-07 | 2026-09-24 | Active | Corporate OSS; revenue unverified |

## 4. Engines, components and signature resources

| Component | Owner / repository | Created | Last push | Status | Purpose / important distinction |
|---|---|---|---|---|---|
| [Intel XED](https://github.com/intelxed/xed) | Intel / `intelxed` | 2016-12-08 | 2026-08-24 | Active | x86 **encoding/decoding** and attributes; not a CFG builder/decompiler |
| [iced-x86](https://github.com/icedland/iced) | `icedland` | 2018-09-07 | 2026-10-13 | Active | Fast x86 decoder/encoder, formatter, instruction metadata; not a full RE pipeline |
| [Capstone](https://github.com/capstone-engine/capstone) | `capstone-engine` | 2013-11-27 | 2026-10-24 | Active | Multi-ISA disassembly and instruction details; not semantic lifting by itself |
| [LLVM MC](https://github.com/llvm/llvm-project) | LLVM community | Monorepo date not checked | Active upstream | Active | Instruction decoding/encoding and TableGen-generated feature predicates; full LLVM IR lifting requires additional logic |
| [SLEIGH](https://ghidra-sre.org/) | Ghidra / NSA | Within Ghidra | Parent active | Active | Declarative ISA encoding **plus p-code semantics**; basis for Ghidra, Kuna, Pyre |
| [GTIRB](https://github.com/GrammaTech/gtirb) | GrammaTech | Not checked | Not checked | ? | Binary structural IR for code/data blocks, CFG, symbols and rewriting; **not equivalent to LLVM IR** |
| [FLIRTDB](https://github.com/Maktm/FLIRTDB) | `Maktm` | 2017-01-04 | 2021-09-03 | Dormant | Community IDA FLIRT **function signature database** |
| [cpp_demangle](https://github.com/gimli-rs/cpp_demangle) | `gimli-rs` | 2016-12-07 | 2026-05-24 | Quiet | Itanium ABI C++ **symbol demangling**, not RTTI recovery |
| [file/libmagic](https://github.com/file/file) | Upstream `file` maintainers; repo is a **mirror** | 2011-01-28 | 2026-10-22 | Mirror active | Magic-number detection; mirror activity is not upstream GitHub development |
| [Siegfried](https://github.com/richardlehane/siegfried) | `richardlehane` | 2014-02-28 | 2026-09-27 | Active | Format identification backed by signature sources like PRONOM |
| [PRONOM](https://www.nationalarchives.gov.uk/PRONOM/) | UK National Archives | N/A | N/A | Service/reference | Registry of file-format signatures |
| [DROID](https://www.nationalarchives.gov.uk/information-management/manage-information/preserving-digital-records/droid/) | UK National Archives | N/A | N/A | Not audited | Digital format identification tooling |
| [Winbindex](https://github.com/m417z/winbindex) | `m417z` | Not checked | Not checked | ? | Windows binary/version corpus useful for external tests |

Other resources from the same exploration: [uops.info](https://uops.info/) (measured latency/throughput), [Agner Fog](https://www.agner.org/optimize/) (optimization manuals), [Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html) (execution/emulation), [MalwareBazaar](https://bazaar.abuse.ch/) (sample corpus), [EMBER](https://github.com/elastic/ember) (malware ML data), [FLIRT](https://hex-rays.com/ida-pro) (function signatures) and [CyberChef](https://gchq.github.io/CyberChef/) (byte transformations).

## 4a. Project-by-project implementation matrix (code analysis)

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

## 5. The actual technical pipeline: different questions, different tools

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

## 6. Feature-area map: formats, language runtimes and resource types

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

## 7. Funding and incentives

| Model | Verified examples / evidence | What cannot be concluded |
|---|---|---|
| Commercial licenses | IDA/Hex-Rays, Binary Ninja | Exact sales, margins, employment or revenue are not public here |
| Open core / commercial services | [rev.ng pricing](https://rev.ng/pricing) describes free core and private/offline/commercial directions | Product availability and paying-customer counts need explicit verification |
| Sponsored academic / government research | [Kuna README](https://github.com/Noelo-Lab/kuna#acknowledgement) names **AFRL**, **Metalware**, **DoD**; release story identifies university/AFRL context | The acknowledgements do not disclose amounts, contract scope or personal compensation |
| Government-developed public tools | NSA Ghidra; GCHQ CyberChef origin | Public development funding does not imply a commercial product |
| Corporate-published OSS | Trail of Bits Checksec Anywhere, GrammaTech Ddisasm, BlackBerry PE Tree, Google's BinDiff/Bloaty | Corporate repository names do not prove dedicated ongoing funding |
| Small independent OSS | x86lint, armlint, Peek-a-Bin, Pyre, PortEx, PeNet, elfx86exts | Public silence about funding is **unknown**, not “free labor” or “zero income” |

**When updating this report:** add funding sources only when they appear in pricing, acknowledgements, official sponsor pages, grant announcements, foundation financials or direct author statements. Avoid guessing revenue from stars, LOC or activity.

## 8. What exists already, and why binary101 can still matter

There is **no claim of first-ever** local browser parsing, PE inspection, ISA detection, function starts, demangling, RTTI, DWARF reading or visualization: mature tools implement each, and some newer projects combine many of them. No single checkbox is a defensible unique selling point.

The opportunity is a **combination and presentation choice**: file-faithful, deeply annotated, cross-linked, client-side analysis of many formats, with particularly careful PE/ELF and runtime metadata, and explicit evidence sources/limitations. This is a different *default workflow* from a code-first decompiler, a malware verdict dashboard or a general-purpose binary editor. Whether users value this enough to prefer it is an **empirical question**; usability testing and side-by-side sample evaluations are better evidence than a “more features” count.

Candidate differentiators to **test and demonstrate**, not merely advertise:

1. A real-world PE with relocations, debug records, NativeAOT or complex resources: side-by-side **field completeness**, semantic explanations, warning fidelity and cross-linked addresses against PE-bear, PortEx, LIEF and Peek-a-Bin.
2. ELF with symbols, DWARF, Go runtime metadata and mixed executable/data regions: compare actual recovered metadata against `readelf`, `llvm-dwarfdump`, Ghidra and Rizin.
3. Instrumented ground-truth binaries with known functions, callbacks and vtables: **precision and recall** of disassembly seeds / reachable-code ISA detection; preserve false positives and false negatives, and report time/memory.
4. Browser privacy: distinguish **local file contents** from fetched static WASM/API assets, remote analytics (if any), and optional external links. Verify using browser network traces.
5. Robustness: malformed-file corpus, differential output, mutation tests, supported-version contracts and reproducer links. Resist claims of “100% correct”.

The README should describe the tool itself in the first screen. Link to this landscape report as **further context**, not as the main product pitch.

## 9. Source register / reproducibility

- Primary inspected project: [binary101 README](https://github.com/Gladskih/binary101/blob/main/README.md), [package.json](https://github.com/Gladskih/binary101/blob/main/package.json), [git tree](https://github.com/Gladskih/binary101/tree/main/analyzers), [Go metadata](https://github.com/Gladskih/binary101/blob/main/docs/go-runtime-metadata.md), [NativeAOT contract](https://github.com/Gladskih/binary101/blob/main/docs/native-aot-metadata.md), [MSVC RTTI contract](https://github.com/Gladskih/binary101/blob/main/docs/msvc-rtti.md), [AArch64 ISA documentation](https://github.com/Gladskih/binary101/blob/main/docs/elf-aarch64-isa.md), [PE import metadata](https://github.com/Gladskih/binary101/blob/main/docs/pe-import-metadata.md).
- GitHub `GET /repos/{owner}/{repo}` `created_at`, `pushed_at`, `archived` for repository rows with exact dates. Example: [x86lint API](https://api.github.com/repos/gaul/x86lint), [Kuna API](https://api.github.com/repos/Noelo-Lab/kuna), [PE Tree API](https://api.github.com/repos/blackberry/pe_tree). An offline snapshot would be needed to reproduce the exact API state in the future.
- Technical primary descriptions: [Kuna](https://github.com/Noelo-Lab/kuna#readme), [Pyre](https://github.com/ant4g0nist/pyre#readme), [RzWeb](https://github.com/IndAlok/rzweb#readme), [Peek-a-Bin](https://github.com/wellingtonlee/peek-a-bin#readme), [x86lint](https://github.com/gaul/x86lint#readme), [Ddisasm](https://github.com/GrammaTech/ddisasm#readme), [rev.ng](https://github.com/revng/revng#readme), [SN4KE paper](https://arxiv.org/abs/2102.05709), [Checksec Anywhere](https://github.com/trailofbits/checksec-anywhere#readme), [die-in-browser](https://github.com/xoreaxlmbdx/die-in-browser#readme), [elfx86exts](https://github.com/pkgw/elfx86exts#readme).
- Monetization anchors: [Kuna acknowledgements](https://github.com/Noelo-Lab/kuna#acknowledgement); [Kuna release background](https://noelo.org/blog/kuna-release/); [rev.ng pricing](https://rev.ng/pricing); vendor sites [Hex-Rays](https://hex-rays.com/ida-pro), [Binary Ninja](https://binary.ninja/).
- Cross-ecosystem details (especially specific decompiler features and licensing) are **high-level mappings**, not source-code audits or reproducible comparative benchmarks.

### Maintenance checklist

- [ ] Re-fetch GitHub `created_at`, `pushed_at`, `archived`, license and upstream READMEs; record the update date.
- [ ] Distinguish repository relocation, rename, archival and project succession from inactivity.
- [ ] Recheck commercial pricing and named grants separately from OSS metadata.
- [ ] Verify technical capability cells against a **specific release/commit**, not current marketing alone.
- [ ] Add a reproducible corpus and quantitative matrix before asserting which tool is “more complete”.