# Binary Analysis Landscape

> **Inventory maintenance: 2026-11-25 (targeted documentation refresh).** New candidate sources last surveyed 2026-11-15; most historical GitHub metadata were captured 2026-10-24 (some entries checked later). `Created`/`Last push` are historical snapshots, **not live values**. Unknown values remain `?`.
>
> Scope: a curated, expanding inventory of file-structure inspectors, binary-format engines, reverse-engineering tools and adjacent forensic/specialist products relevant to [binary101](https://github.com/Gladskih/binary101). This is neither a claim of completeness nor a benchmark.

**Corpus structure:** This file is the **canonical inventory of post-build binary analysis tools** (identity, scope, primary references and recorded snapshots). [Binary Analysis Evaluation](binary-analysis-evaluation.md) owns capability claims, evidence definitions and comparison results. [Binary Analysis Techniques](binary-analysis-techniques.md) owns technical distinctions and algorithmic methods. [Compiler Exploration Landscape](compiler-exploration-landscape.md) is the separate, canonical inventory of **source-to-assembly/compiler exploration tools**. Cross-domain mentions are contextual, not new catalog entries.

## Scope and interpretation

**Product, engine and upstream are different entities.** An in-browser wrapper around an existing engine is a distinct product but must credit its upstream. Use the first-listed section as the project's canonical catalog entry; other documents should link to it.

**Dates.** `Created` is GitHub repository creation, not invention of a product. `Last push` is GitHub `pushed_at` at the earlier recorded snapshot and does not prove a release or ongoing maintenance. Status labels in historical rows refer **only to that recorded snapshot**, never to the current date; new entries may have no established status.

**Evidence.** Follow the [controlled evidence vocabulary and scope rules](binary-analysis-evaluation.md#evidence-and-claim-records). Product-page claims, observed source code, test outcomes and independently reproduced behavior are distinct; a reachable site or CI badge does not prove a capability.

**Ownership / funding.** Owner namespace does not identify the only contributor, legal owner or funder. `Unverified` means unknown, not unsupported or unpaid. GitHub stars are attention, not engineering quality.

**Abbreviations.** PE = Portable Executable; ELF = Executable and Linkable Format; MO = Mach-O; RE = reverse engineering; CFG = control-flow graph; IR = intermediate representation; RTTI = runtime type information; FID = function identification; R2R = ReadyToRun; AOT = ahead-of-time compilation. `?` = not established; `—` = not central to the product, not proof of absence.

## Structural inspection and programmable binary-format tools

This family is central to comparing file-first analysis workflows. **One row per project family** here; details about comparative strengths belong in [evaluation](binary-analysis-evaluation.md), not a second duplicate inventory. Entries are sourced to official documentation or project repositories; **present in the code / runtime-verified / deep format support** are separate claims.

| Project / primary reference | Primary model | Interaction and extension model | Source / evidence as recorded (through 2026-11-15) |
|---|---|---|---|
| [ImHex](https://github.com/WerWolv/ImHex) · [patterns](https://github.com/WerWolv/ImHex-Patterns) | Programmable structure-aware hex editor | Pattern Language, format definitions, native and web usage | Official repository/documentation; depth on common test corpus **not checked** |
| [ReHex](https://github.com/solemnwarning/rehex) | Reverse-engineering hex editor | Byte-range annotations, inline disassembly, Lua scripting and binary diff | [Project README](https://github.com/solemnwarning/rehex); general-purpose editor, not an automatic deep PE parser |
| [010 Editor](https://www.sweetscape.com/010editor/) · [templates](https://www.sweetscape.com/010editor/repository/) | Hex/text editor with Binary Templates | C-like templates, scripts, structured editing | Vendor documentation; exact latest version **not checked** |
| [Kaitai Struct + Web IDE](https://kaitai.io/) · [IDE](https://ide.kaitai.io/) | Declarative binary-format specification and visual inspection | KSY schemas, generated parsers, in-browser Web IDE | [User guide](https://doc.kaitai.io/user_guide) |
| [fq](https://github.com/wader/fq) · [manual](https://wader.github.io/fq/) | Queryable structural binary decoder | jq-style expressions, nested decoding, structural hex, REPL | Primary source and command manual |
| [Cerbero Suite](https://cerbero.io/) | Extensible binary analysis / forensic workspace | Built-in format inspectors, scripts, extensibility | Vendor documentation; exact format-depth matrix **not checked** |
| [Hexinator](https://hexinator.com/) | Grammar-driven binary file inspector/editor | Grammars for file layouts | Vendor documentation; runtime **not checked** |
| [Synalyze It!](https://www.synalysis.net/) | Binary-file inspection via grammars | Format grammars, hex/structure alignment | Vendor documentation; runtime **not checked** |
| [Hachoir](https://github.com/vstinner/hachoir) | Bit/byte-oriented parser framework | Code-defined hierarchical fields and format parsers | Source repository; exact maintenance state **not checked** |
| [HexEd.it](https://hexed.it/) | Local browser hex editor | Binary editing and format identification; structural depth varies | Product site; not equivalent to deep parsing |
| [Ufex](https://github.com/ufex/Ufex) | Cross-platform desktop structural file explorer | Plugin-supplied format parsing, field tree and byte mapping | Repo README; format-specific depth **not checked** |

**Avoid counting a signature match as a format parser.** Separate recognition, header parsing, full structure traversal, semantic interpretation, verification and editing; formats can be supported at very different depths. Terms like “hundreds of formats” must be scoped accordingly.

## Browser-based analyzers and adjacent projects

| Project | Scope and distinguishing idea | Owner / maintainer context | Created | Last push | Status at snapshot | Business / funding |
|---|---|---|---|---|---|---|
| [**binary101**](https://github.com/Gladskih/binary101) | Local, file-oriented structural and semantic inspection; deep PE/ELF work | `Gladskih` | 2025-11-10 | 2026-10-24 | Active | Personal OSS; no published revenue claim |
| [**binkeep**](https://github.com/kano92-dir/binkeep) · [demo](https://kano92-dir.github.io/binkeep/) | Local-browser PE/ELF/Mach-O triage: Capstone WASM, functions/xrefs, .NET/APK/DEX, YARA and file diff; **decompiler is planned** | `kano92-dir` | ? | ? | Repo/site described; sample output not independently checked | MIT OSS (per [guide](https://kano92-dir.github.io/binkeep/guide.html)) |
| [**ATLAS**](https://github.com/GreenShoeGarage/Atlas) | Local-browser PE/ELF structure, limited x86/Thumb disassembly, CFG, developing x86 LIR/pseudocode and optional local debugger bridge | `GreenShoeGarage` | ? | ? | v1.0 README and bundled builds examined as listings; runtime not tested | GPL-3.0 OSS |
| [**Bytes Revealer**](https://github.com/vulnex/bytesrevealer) · [demo](https://bytesrevealer.online/) | Browser hex/entropy/strings, PE/ELF/Mach-O indicators, embedded executable carving, YARA and Kaitai grammars | `vulnex` | ? | ? | README claim; full analyses limited to <50 MB in documented version | Apache-2.0 OSS |
| [**PE Parser**](https://www.peparser.com/en) | Browser-local PE triage: Rust/WASM, code and runtime analysis, unpacking, batch reporting | Cyber Experts (per [terms](https://www.peparser.com/en/terms)) | ? | N/A | [Dated public documentation](https://www.peparser.com/en/blog/pe-file-format-forensics-guide) from 2026-09-20 (not a launch date); site checked 2026-11-25, runtime/source not audited | Free website; implementation license and funding unverified |
| [**Binary Forensics**](https://www.ethanjhulbert.org/digital-forensics/binary-forensics/) | Browser PE/ELF/Mach-O/Wasm structural triage, hex map, entropy and JSON export | Ethan J. Hulbert (site attribution) | ? | N/A | Website description only; code/version not audited | Unverified |
| [**Dissect**](https://github.com/sammwyy/dissect) | Browser-local PE/ELF/Mach-O inspection, Capstone disassembly and in-place patching; narrow Authenticode integrity check, not CMS trust verification | `sammwyy` | 2026-06-11 | 2026-06-11 | One initial commit as checked 2026-11-08; no separate tests or CI located | Unverified |
| [**Loupe**](https://github.com/Loupe-tools/Loupe) · [demo](https://loupe.tools/) | Offline single-HTML security/forensic triage: executable, document, email, log, and network formats; deobfuscation and evidence export | `Loupe-tools` | 2026-04-11 | 2026-11-01 | Active; repository includes tests and sample corpus | Unverified |
| [**SPECTRA**](https://github.com/ekomsSavior/SPECTRA) | Browser RE workbench integrating third-party WASM engines for disassembly, decompilation, and emulation | `ekomsSavior` | 2026-10-14 | 2026-10-20 | New; broad README claims, upstream engines present; functionality not independently benchmarked | Unverified |
| [**Universal File Analyser**](https://github.com/KostaJovanovic/Universal-File-Analyser) | Local browser file identification and cross-domain viewers (media, documents, CAD, etc.) | `KostaJovanovic` | 2026-06-01 | 2026-10-29 | Active; distinguish cataloged format pages from deep parsers | Unverified |
| [**ELF Viewer**](https://github.com/kariya-mitsuru/elf-viewer) | Wails desktop app with web frontend for ELF structures and memory maps | `kariya-mitsuru` | 2026-03-01 | 2026-03-21 | Quiet; specialized | Unverified |
| [**Kuna**](https://github.com/Noelo-Lab/kuna) | Rust port/evolution of Ghidra decompiler, agent-oriented; browser/CLI/Ghidra | `Noelo-Lab`; lead **Zion Basque** | 2026-06-07 | 2026-10-24 | Active | **Sponsor**: AFRL, Metalware, DoD explicitly thanked |
| [**Pyre**](https://github.com/ant4g0nist/pyre) | Real Ghidra C++ decompiler in WebAssembly, SLEIGH specs loaded on demand | `ant4g0nist` | 2026-05-04 | 2026-05-04 | Quiet; alpha | Unverified |
| [**Peek-a-Bin**](https://github.com/wellingtonlee/peek-a-bin) · [demo](https://wellingtonlee.github.io/peek-a-bin/) | Browser PE disassembler, xrefs, CFG, own SSA/IR decompiler, annotations | `wellingtonlee` | 2026-02-13 | 2026-10-08 | Active | Unverified |
| [**RzWeb**](https://github.com/IndAlok/rzweb) · [demo](https://rizin.pages.dev/) | Complete Rizin environment compiled to WASM | `IndAlok`; depends on Rizin and `rzwasi` | 2026-01-15 | 2026-10-24 | Active | Unverified |
| [**SalSA Web**](https://github.com/a-rey/SalSA) · [demo](https://a-rey.github.io/SalSA/) | Browser deep-dive PE parser, derived from DoD SalSA | `a-rey`; upstream `deptofdefense/SalSA` | 2019-05-30 | 2020-05-08 | Dormant | Unverified |
| [**Checksec Anywhere**](https://github.com/trailofbits/checksec-anywhere) · [demo](https://checksec-anywhere.com/) | In-browser PE/ELF/MO security-feature checks, bulk reports, SARIF | `trailofbits` | 2025-06-02 | 2026-10-20 | Active | Company OSS; Trail of Bits offers security consulting; **not evidence of product revenue** |
| [**die-in-browser**](https://github.com/xoreaxlmbdx/die-in-browser) | Full Detect It Easy inside Linux-on-v86 browser emulator | `xoreaxlmbdx` | 2025-12-28 | 2026-07-23 | Quiet at 2026-10-24 snapshot | Unverified |
| [**Infectio**](https://github.com/filippofinke/infectio) · [demo](https://infectio.filippofinke.ch/) | Rust/WASM local malware triage across binaries, documents and archives; optional local LLM | `filippofinke` | 2025-10-12 | 2025-10-12 | Dormant | Unverified |
| [**Online Cyber Tools PE Analyzer**](https://onlinecybertools.com/tools/reverse-engineering/pe-analyzer) | Online PE headers, imports/exports, disassembly, strings and anomaly inspection | Owner not established | ? | N/A | Website; lifecycle unverified | Unverified |
| [**Binary Triage**](https://qbitz.foo/binary-triage/index.html) | Browser PE triage, entropy, signatures and suspicious indicators | Owner/repository not established | ? | N/A | Website; lifecycle unverified | Unverified |
| [**Dogbolt**](https://dogbolt.org/) | Compare outputs of multiple decompilers, usually via hosted backends | Public-service operators; maintainer not checked | ? | N/A | Service availability not audited | Unverified |

**Important architectural distinction:** local browser parsing does not make products equivalent. `RzWeb` runs a comprehensive native RE engine in WASM; `Pyre` ports a C++ decompiler; `Kuna` ships a Rust decompiler core; `die-in-browser` boots a miniature guest OS; `binary101` is deliberately a file-structure-first inspector with independent semantic analyses.

## Desktop suites, format parsers, malware tools

| Project | Primary role | Owner / stewardship | Created | Last push | Status at snapshot | Economics |
|---|---|---|---|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Full RE suite: disassembly, SLEIGH/p-code, analysis, decompilation, **Version Tracking** for binary comparison | US **NSA** | 2019-03-01 | 2026-10-22 | Active | Government-developed OSS; not a paid license product |
| [IDA + Hex-Rays](https://hex-rays.com/ida-pro) | Professional RE/disassembly/decompilation | **Hex-Rays** | N/A | N/A | Commercial product | **Commercial** licenses |
| [Binary Ninja API](https://github.com/Vector35/binaryninja-api) | Public API and extensions for the Binary Ninja product | **Vector 35** | 2015-10-30 | 2026-10-23 | Active | **Commercial** main product |
| [Rizin](https://github.com/rizinorg/rizin) | Open RE framework, RzIL, analysis, patching | `rizinorg` community | 2020-09-30 | 2026-10-24 | Active | OSS; funding not established |
| [radare2](https://github.com/radareorg/radare2) | CLI-oriented RE framework, ESIL | `radareorg` community | 2012-07-03 | 2026-10-24 | Active | OSS; funding not established |
| [Cutter](https://github.com/rizinorg/cutter) | GUI for Rizin | `rizinorg` | 2017-09-25 | 2026-09-11 | Active | OSS; funding not established |
| [**Reko**](https://github.com/uxmal/reko) | Executable format loaders, machine-code analysis and decompilation (distinct from structural-only inspection) | `uxmal` | ? | ? | [README](https://github.com/uxmal/reko); architecture/loader maturity varies | OSS; exact licensing by component must be checked |
| [**RetDec**](https://github.com/avast/retdec) | LLVM-based PE/ELF/Mach-O/COFF/AR decompiler, structure/debug loading and CFG | Avast-originated OSS | ? | ? | README explicitly states **limited maintenance**; not equated to active development | MIT core and third-party component licenses |
| [**angr**](https://github.com/angr/angr) | Multi-architecture binary lifting and static/symbolic program analysis | `angr` community | ? | ? | [Official quickstart](https://github.com/angr/angr/blob/master/docs/quickstart.rst); specialized framework, not PE editor | OSS; economics unverified |
| [**CMU BAP**](https://github.com/BinaryAnalysisPlatform/bap) | IR/CFG, binary program analysis, interpreter, symbolic execution and extension framework | Carnegie Mellon-originated research | ? | ? | [README](https://github.com/BinaryAnalysisPlatform/bap); distinct from general file format GUI | MIT OSS; historical sponsors named in README |
| [LIEF](https://github.com/lief-project/LIEF) | PE/ELF/MO parser/editor/instrumentation library (C++/Python/Rust) | `lief-project` | 2017-03-16 | 2026-10-22 | Active | OSS; financial model not established |
| [PortEx](https://github.com/struppigel/PortEx) · [PortexAnalyzerGUI](https://github.com/struppigel/PortexAnalyzerGUI) | Java PE parser; companion GUI adds structure/entropy/overlay/malware triage views | `struppigel` | 2013-09-27 | 2026-10-21 | Parent active at prior snapshot; GUI separately maintained | [Author calls it a hobby](https://github.com/struppigel/PortexAnalyzerGUI); other funding unverified |
| [PeNet](https://github.com/secana/PeNet) | .NET PE parser library | `secana` | 2015-07-02 | 2026-10-15 | Active at prior snapshot | Unverified |
| [**PPEE / puppy**](https://www.mzrst.com/) · [v2 docs](https://www.mzrst.com/puppy/docs/) | PE-only inspector/editor and anomaly detector; v2 preview documents **x64 unwind/prologue-vs-code checks**, CLI/JSON/MCP and runtime recognizers | Independent product; developer identity not independently established | ? | N/A | v1.16 stable listed 2026-08-31; **v2 preview** documentation dated 2026-10-09; [exception checks](https://www.mzrst.com/puppy/docs/features/data-directories/exception/) described, not reproduced | Free binaries; source availability/license unverified |
| [**Malcat**](https://malcat.fr/) · [parser matrix](https://doc.malcat.fr/analysis/filetypes.html) | File-first multi-format dissection, editing, malware triage; native disassemblers, CFG and edition-dependent SLEIGH decompilation | Malcat / vendor; developer entity not audited | ? | N/A | [Docs](https://doc.malcat.fr/), [editions](https://malcat.fr/download.html); advertised features, no side-by-side run | Free noncommercial Lite; paid Full/Pro |
| [**pestudio**](https://www.winitor.com/) | PE static malware indicators, strings/imports/manifest/metadata and optional batch reports | Winitor; Marc Ochsenmeier | ? | N/A | [Edition matrix](https://www.winitor.com/download); not a general decompiler | Free private Basic; paid Professional |
| [**PE Explorer**](https://www.heaventools.com/pe-explorer.htm) | Windows PE header/section/resource editor, dependencies, signature viewer, static unpackers and x86 disassembler | Heaventools Software | ? | N/A | [Features](https://www.heaventools.com/pe-explorer-feature-list.htm); x64 disassembler support **not** inferred from 64-bit host/file marketing | Commercial trial/licenses |
| [**XELFViewer**](https://github.com/horsicq/XELFViewer) | Desktop ELF structure viewer/editor | `horsicq` | ? | ? | README; exact parsing depth and release recency not assessed | MIT OSS |
| [**ELF Dissector**](https://github.com/KDE/elf-dissector) | ELF dependencies, relocations, size profiling, DWARF type layouts; x86/AArch64 disassembly | KDE project | ? | ? | [Project README](https://github.com/KDE/elf-dissector); experimental CLI facilities not treated as general GUI coverage | KDE OSS; licensing/release state verify per packaging |
| [**binsider**](https://github.com/orhun/binsider) | ELF TUI with sections, symbols, dependencies, hex, strings and optional runtime tracing | `orhun` | ? | ? | [Official quickstart](https://binsider.dev/getting-started/); no byte-level comparison run | MIT / Apache-2.0 OSS |
| [**DWARF Explorer / dwex**](https://github.com/sevaa/dwex) | Navigable DWARF DIE/reference GUI in ELF/Mach-O/PE/Wasm/ar, not a general executable decompiler | `sevaa` | ? | ? | README; inherits pyelftools scope and limitations | BSD-3-Clause OSS |
| [**Dependencies**](https://github.com/lucasg/Dependencies) | Windows loader-linkage GUI/CLI: direct/forwarded/delay imports, API sets and SxS approximation | `lucasg` | ? | ? | [README](https://github.com/lucasg/Dependencies); **not** dynamic LoadLibrary resolution | MIT OSS |
| [Binocular](https://hunterworks.software/binocular/) | Binary inspection and structural comparison | Project stewardship not established | ? | N/A | Unverified | Unverified |
| [Crush Forensics](https://github.com/kalink0/crush-forensics) | Read-only forensic workbench for archives, disk images, mobile backups and nested structured data | `kalink0` | 2026-03-15 | 2026-11-06 | Active; test/audit tooling documented | Unverified |
| [unblob](https://github.com/onekey-sec/unblob) | Exact-range extraction and recursive analysis of embedded data in firmware and containers | `onekey-sec` | 2021-06-08 | 2026-11-05 | Active | Unverified |
| [binviz](https://github.com/karankantaria/binviz) | Byte/entropy/CFG visualization across a shared address-space model | `karankantaria` | 2026-08-03 | 2026-08-26 | Quiet; specialized | Unverified |
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

`pe-bear` has an older project history than the current GitHub repository's 2022 creation date. **Do not confuse repo dates with invention dates.** Ghidra Version Tracking is a feature of Ghidra, not an additional independent project.

## ISA analytics, semantic diagnostics and binary rewriting

| Project | Principal method | Owner | Created | Last push | Status at snapshot | Economics |
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
| [VBinDiff](https://www.cjmweb.net/vbindiff/) | Byte-level hex differencing | Historical independent tool | ? | N/A | Unverified | Unverified |
| [Bloaty](https://github.com/google/bloaty) | Binary *size attribution*, not decompilation | `google` | 2016-11-07 | 2026-09-24 | Active | Corporate OSS; revenue unverified |

## Engines, components and signature resources

| Component | Owner / repository | Created | Last push | Status at snapshot | Purpose / important distinction |
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

## Funding and incentives

| Model | Verified examples / evidence | What cannot be concluded |
|---|---|---|
| Commercial licenses | IDA/Hex-Rays, Binary Ninja | Exact sales, margins, employment or revenue are not public here |
| Open core / commercial services | [rev.ng pricing](https://rev.ng/pricing) describes free core and private/offline/commercial directions | Product availability and paying-customer counts need explicit verification |
| Sponsored academic / government research | [Kuna README](https://github.com/Noelo-Lab/kuna#acknowledgement) names **AFRL**, **Metalware**, **DoD**; release story identifies university/AFRL context | The acknowledgements do not disclose amounts, contract scope or personal compensation |
| Government-developed public tools | NSA Ghidra; GCHQ CyberChef origin | Public development funding does not imply a commercial product |
| Corporate-published OSS | Trail of Bits Checksec Anywhere, GrammaTech Ddisasm, BlackBerry PE Tree, Google's BinDiff/Bloaty | Corporate repository names do not prove dedicated ongoing funding |
| Small independent OSS | x86lint, armlint, Peek-a-Bin, Pyre, PortEx, PeNet, elfx86exts | Public silence about funding is **unknown**, not “free labor” or “zero income” |

**When updating this report:** add funding sources only when they appear in pricing, acknowledgements, official sponsor pages, grant announcements, foundation financials or direct author statements. Avoid guessing revenue from stars, LOC or activity.

## Sources and reproducibility

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

### New sources and evidence added 2026-11-15

- PE-focused non-GitHub products: [PPEE v2 Exception Directory](https://www.mzrst.com/puppy/docs/features/data-directories/exception/) (explicit instruction-versus-unwind diagnostics, documented only), [pestudio tiers](https://www.winitor.com/download), [PE Explorer features](https://www.heaventools.com/pe-explorer-feature-list.htm), [PE Parser site](https://www.peparser.com/en). This category was under-sampled in the previous survey.
- Wider file-first tooling: [Malcat parser matrix](https://doc.malcat.fr/analysis/filetypes.html), [Malcat code-analysis matrix](https://doc.malcat.fr/analysis/disassembly.html), [KDE ELF Dissector](https://github.com/KDE/elf-dissector), [XELFViewer](https://github.com/horsicq/XELFViewer), [binsider](https://binsider.dev/getting-started/), [dwex](https://github.com/sevaa/dwex), [Dependencies](https://github.com/lucasg/Dependencies), [PortexAnalyzerGUI](https://github.com/struppigel/PortexAnalyzerGUI), [ReHex](https://github.com/solemnwarning/rehex), [RetDec](https://github.com/avast/retdec), [angr](https://github.com/angr/angr), [BAP](https://github.com/BinaryAnalysisPlatform/bap).
- Browser search beyond previous shortlist: [binkeep guide](https://kano92-dir.github.io/binkeep/guide.html), [ATLAS](https://github.com/GreenShoeGarage/Atlas), [Bytes Revealer](https://github.com/vulnex/bytesrevealer), [Binary Forensics](https://www.ethanjhulbert.org/digital-forensics/binary-forensics/). The last two have materially different depth/size constraints; claims are **not** independently benchmarked.
- Discovery approach: cross-check native vendors, format-specific ELF tools, browser/offline tools, RE/DFIR directories and GitHub projects. Findings are curated for overlapping workflows; **not an exhaustive census** of all PE/ELF viewers, forks, malware triage scripts or hex editors.
- **No tool was executed on a shared fixture in this update.** All new feature assertions remain source-described. Preserve a concrete version/commit and a [reproducible test ledger](binary-analysis-evaluation.md) before claiming correctness, completeness or superiority.

### New sources and evidence added 2026-11-08

- Structural systems: [ImHex](https://github.com/WerWolv/ImHex), [010 Editor](https://www.sweetscape.com/010editor/), [Kaitai Struct guide](https://doc.kaitai.io/user_guide), [fq](https://github.com/wader/fq), [Cerbero](https://cerbero.io/), [Hexinator](https://hexinator.com/), [Synalyze It!](https://www.synalysis.net/), [Hachoir](https://github.com/vstinner/hachoir), [Ufex](https://github.com/ufex/Ufex).
- Browser/local adjacency: [Dissect](https://github.com/sammwyy/dissect), [Loupe](https://github.com/Loupe-tools/Loupe), [SPECTRA](https://github.com/ekomsSavior/SPECTRA), [Universal File Analyser](https://github.com/KostaJovanovic/Universal-File-Analyser), [ELF Viewer](https://github.com/kariya-mitsuru/elf-viewer).
- Firmware/forensics: [unblob](https://github.com/onekey-sec/unblob), [Crush Forensics](https://github.com/kalink0/crush-forensics), [binviz](https://github.com/karankantaria/binviz).
- Snapshot evidence for Dissect: [initial source commit](https://github.com/sammwyy/dissect/commit/7f5d3e6), [Authenticode implementation](https://github.com/sammwyy/dissect/blob/main/src/formats/pe/authenticode.ts). This is evidence of implementation scope, not of malicious intent or source authorship.

### Coverage gaps and update discipline

- Search by **user workflow and technical approach**, not just by previously discussed features: format editors, grammars, query engines, forensics, firmware extraction, browser inspectors, executable internals, malware triage, disassembly, binary rewriting, size/ISA tools.
- Keep one canonical entry per product family; use links (not copied tables) in evaluation notes. Record parent/port/wrapper relations.
- Treat missing evidence as **unknown**, not `no`. For a feature assertion, cite a specific product document, version/commit, code path or test result.
- Avoid mass-refreshing “last push” to today's date without actually querying each repo.
- Prefer fixed test samples and reproducible commands for rankings; store results only in the [evaluation document](binary-analysis-evaluation.md#comparison-results-ledger).
- For source-to-assembly tools use the [compiler exploration inventory](compiler-exploration-landscape.md) as the canonical list; avoid copying its full rows here.
