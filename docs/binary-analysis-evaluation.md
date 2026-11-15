# Binary Analysis Evaluation

> Updated 2026-11-15. Comparison methodology and research backlog. [Canonical catalog](binary-analysis-landscape.md) · [Technical approaches](binary-analysis-techniques.md).
>
> **Do not turn README promises, file counts, stars, or tool labels into tested feature coverage.** No cross-tool executable corpus or performance benchmark was completed in this revision.

## Axes for a meaningful comparison

| Dimension | What to assess | Common false equivalence |
|---|---|---|
| Recognition | Detects file family correctly, including malformed and embedded cases | Signature match = parser |
| Structural depth | Decodes on-disk fields, variants, tables, unknown/reserved bytes, ordering | Header display = complete analysis |
| Semantics | Validates references, derived values and runtime-specific metadata | A displayed value = validated meaning |
| Evidence and provenance | Maps each observation to exact offsets/ranges and input source | Guess/heuristic = authoritative record |
| Robustness | Truncation, overlap, weird endian/version, adversarial payloads | Successful demo = safe parser |
| Nested structures | Traverses containers, reports boundaries, prevents ambiguous child offsets | Recursive filename search = nested decoding |
| Code analysis | Source of disassembly seeds, architectures, CFG/IR/decompilation | Decoder = lifter = decompiler |
| Workflow | Browser/offline, no upload, large files, search, xrefs, scripting, plugins, editing | Similar screenshots = similar workflow |
| Verification | Test corpus, differential oracles, fuzzing, reproducible build | Stars, LOC, CI badge = correctness |

For each capability record `claimed` (vendor/README), `code-observed` (file and commit), `test-observed` (specific test/run), `sample-verified` (known input/output), or `unknown`. These are **evidence types, not a score**; a single module can have multiple. Preserve explicit unsupported/non-goals separately.

## Tool families and outstanding comparisons

| Family | Representative tools (see catalog for canonical entries) | Relevance to binary101 | Verification still needed |
|---|---|---|---|
| Programmable structure/hex | ImHex, 010 Editor, Hexinator, Synalyze It! | User-defined formats, bytes-field sync, editing and visualization | Compare automatic depth versus grammar/template setup burden |
| Declarative parsers | Kaitai Struct / Web IDE, Hachoir | Format schemas, generated parsers, byte-level fields | Schema coverage and unusual-format correctness |
| Queryable binary structures | fq | Query model, nested decoders, field-to-byte provenance | Ergonomics/precision on complex PE/ELF metadata |
| Professional structural / forensic | Cerbero Suite, Malcat, Crush Forensics, Ufex | File-native investigation, nested views, structured explanations | Edition-dependent capabilities and sample-level completeness |
| Browser/local inspectors | Dissect, Loupe, binkeep, PE Parser, Bytes Revealer, ATLAS, Universal File Analyser, ELF Viewer | No-upload UX, varied domain-specific viewers | Parsing depth, tests, offline network behavior, malformed cases |
| Browser RE workbenches | RzWeb, SPECTRA, Pyre, Peek-a-Bin, Kuna | Code-first discovery and engine reuse | Distinguish WASM engine reuse from novel semantics/decompiler implementation |
| Embedded/firmware recovery | unblob, Binwalk | Precise child ranges, extraction, unknown segments | Differential checks on nested/overlapping payloads |
| Dedicated PE inspection / triage | PPEE, pestudio, PE Explorer, PE-bear, PortEx/PortexAnalyzerGUI | Overlapping PE data directories, anomaly checks, editing and runtime metadata | Compare actual fields, x64 prologue checks, malformed cases and editions |
| Dedicated ELF / DWARF inspection | KDE ELF Dissector, XELFViewer, binsider, dwex | ELF linking/relocations, layout/size, DWARF navigation | Compare relocations, stripped inputs, separate-debug and runtime metadata |
| Windows loader dependency diagnostics | Dependencies | API sets, delay imports, forwarders, SxS and library-resolution context | File imports do not imply real dynamic binding |


### Compact capability comparison (source-described; **not benchmarked**)

`D` = explicitly documented in linked first-party source; `P` = documented partial/specialized coverage; `?` = not established (never assume absence); `—` = outside stated primary role. `D` does **not** mean we ran the tool or proved correctness. Features may be edition/version-dependent.

| Tool / primary evidence | PE | ELF | Mach-O | Code analysis | Unwind-versus-code check | Workflow / critical limit |
|---|:---:|:---:|:---:|---|---|---|
| [binary101](https://github.com/Gladskih/binary101) | D | D | P | D: seed-guided reachable-code CFG; no C decompiler | ? (prologue validator not established) | Browser-local, metadata-first; scope varies by commit |
| [PPEE v2 preview](https://www.mzrst.com/puppy/docs/features/data-directories/exception/) | D | — | — | D: x86/x64 code analysis | **D: x64 prologue**; full function **?** | GUI/CLI/JSON/MCP; v2 preview differs from v1.16 |
| [Malcat](https://doc.malcat.fr/analysis/filetypes.html) · [code](https://doc.malcat.fr/analysis/disassembly.html) | D | D | D | D: disassembly, CFG, SLEIGH decompiler | ? | Multi-format dissection; free Lite limited |
| [PE-bear](https://github.com/hasherezade/pe-bear) | D | — | — | ? | ? | PE-oriented GUI inspection and editing |
| [PortEx / AnalyzerGUI](https://github.com/struppigel/PortexAnalyzerGUI) | D | — | — | ? | ? | Java PE parser, separate visualizer |
| [pestudio](https://www.winitor.com/download) | D | — | — | ? | ? | Malware indicators; professional batch/ATT&CK paid |
| [PE Explorer](https://www.heaventools.com/pe-explorer-feature-list.htm) | D | — | — | D: **x86** disassembler | ? | Resource/section editor, static unpackers |
| [binkeep](https://kano92-dir.github.io/binkeep/guide.html) | D | D | D | D: Capstone, linear-sweep functions, CFG | ? | Local browser; decompiler **planned** |
| [ATLAS](https://github.com/GreenShoeGarage/Atlas) | P | P | ? | P: x86/x64 and Thumb core decode, CFG, evolving x86 LIR | ? | Browser + optional bridge; incomplete ISA and parsers |
| [PE Parser](https://www.peparser.com/en) | D | — | — | P: selected x86/x64 code emulation | ? | Browser PE batches, YARA and UPX |
| [Bytes Revealer](https://github.com/vulnex/bytesrevealer) | D | D | D | ? (disassembly on roadmap) | ? | Kaitai/YARA/hex; full analysis <50 MB per README |
| [KDE ELF Dissector](https://github.com/KDE/elf-dissector) | — | D | — | D: x86/AArch64 disassembly | ? | Relocation/dependency/size profiling; some CLI experimental |
| [XELFViewer](https://github.com/horsicq/XELFViewer) | — | D | — | ? | ? | ELF GUI editor/inspector |
| [binsider](https://binsider.dev/getting-started/) | — | D | — | — | ? | ELF TUI and optional dynamic trace |
| [dwex](https://github.com/sevaa/dwex) | P | P | P | — | ? | DWARF DIE navigator, also Wasm/ar |
| [Dependencies](https://github.com/lucasg/Dependencies) | P | — | — | — | ? | Windows imports/API sets/delays; no dynamic LoadLibrary |

**Precise distinction:** viewing `.pdata`/`.xdata` is not instruction-level validation; decoding a prologue is not whole-function control-flow/data-flow verification; displaying ELF `.eh_frame` is not checking code against CFI. A missing feature claim is `?` until inspected or tested.

### Broad-format counts need decomposition

The number of file types listed in a format registry, signatures database or generated website catalog is not the number of independent deep parsers. Treat `recognized`, `parsed`, `traversed`, `semantically interpreted`, `cryptographically verified`, and `editable` as distinct claims. In particular, do not convert broad-format marketing into cross-tool capability scores without sample execution.

## Reproducible comparison corpus to build

| Case | Evidence to compare | Suggested comparators |
|---|---|---|
| Modern MSVC PE with RTTI and exception metadata | Raw record order, validated references, complete/extensible tree, ambiguity | binary101, PPEE v2, Malcat, PE-bear, PortEx, ImHex patterns, Cerbero |
| Signed PE with complex Authenticode | CMS vs PE digest, signer verification, trust, timestamps, failure modes | Binary101, Cerbero, LIEF, Dissect; specific signature validators as oracle |
| .NET NativeAOT / ReadyToRun PE | Metadata/ownership graph, well-supported version layouts, false seeds | Binary101, Ghidra, specialized .NET tools |
| ELF with DWARF, relocations and Go metadata | Exact sections/tags, addresses, raw ranges and orphan data | binary101, KDE ELF Dissector, XELFViewer, binsider, dwex, readelf, llvm-dwarfdump, Ghidra |
| Nested archive/resource and damaged sample | Exact parent/child mapping, extraction boundaries, non-recursive failures | Binary101, unblob, Cerbero, Loupe, fq |
| Hand-crafted malformed/overlapping PE/ELF | Crashes, hangs, false positives, warning precision, resource limits | binary101, PPEE, Malcat, PortEx, LIEF, Kaitai and specialized parsers |
| x64 PE altered prologue with matched unmodified control | `UNWIND_INFO` op offsets vs actual bytes; warning precision and false positives | PPEE v2 preview; binary101 only after implementing the validator; `llvm-readobj --unwind` for metadata |
| x64 PE valid noncanonical prologues, chained records and epilogues | Prevent false mismatch on legitimate compiler/assembly cases, including probes and shrink wrapping | PPEE v2 preview, MSVC/Clang fixtures, WinDbg where possible |
| x64 PE body-only frame/stack mutation | Determine whether a checker actually performs path-sensitive **full-function** analysis | Separate experimental CFG/dataflow validator; PPEE full-function support unverified |
| ELF PLT/GOT, RELR, versioning and stripped/sectionless binaries | Confirm each decoded/linkage relationship with address evidence | binary101, KDE ELF Dissector, LIEF, readelf, objdump |

Record the fixture SHA-256 and provenance, exact versions/commits, platform, commands, expected observations, outputs and failures. **No comparative winners should be declared until this ledger exists.**

### Comparison results ledger

| Fixture SHA-256 | Producer / exact version | Expected observation | Tool / exact build | Invocation | Output reference | Outcome |
|---|---|---|---|---|---|---|
| *Pending* | *Pending* | *Pending* | *Pending* | *Pending* | *Pending* | **Not tested** |

Vendor sample anecdotes, including PPEE's unusual `coreclr.dll` stubs, are **not our measurements**. A mismatch is not in itself a demonstrated compiler bug, malicious hook or actual unwinding failure. Use an unchanged control specimen, capture full outputs and independently check each finding.

## Inclusion and maintenance

Maintain a standing discovery backlog by workflow: structured editors, grammars, CLI query/decoding, malware/DFIR, RE and lifting, firmware/nested extraction, ISA diagnostics, debug/ABI/runtime metadata, file recognition and very-large-file UI. Revisit the catalog by category and explicitly search non-GitHub proprietary PE tools, older Windows PE viewers and ELF-specific desktop utilities; do not only follow features discussed previously. New candidates belong in the catalog once identity and primary source are verified; deeper claims belong here with evidence.


## How binary101 can differentiate (hypotheses, not rankings)

There is **no claim of first-ever** local browser parsing, PE inspection, ISA detection, function starts, demangling, RTTI, DWARF reading or visualization: mature tools implement each, and some newer projects combine many of them. No single checkbox is a defensible unique selling point.

The opportunity is a **combination and presentation choice**: file-faithful, deeply annotated, cross-linked, client-side analysis of many formats, with particularly careful PE/ELF and runtime metadata, and explicit evidence sources/limitations. This is a different *default workflow* from a code-first decompiler, a malware verdict dashboard or a general-purpose binary editor. Whether users value this enough to prefer it is an **empirical question**; usability testing and side-by-side sample evaluations are better evidence than a “more features” count.

Candidate differentiators to **test and demonstrate**, not merely advertise:

1. A real-world PE with relocations, debug records, NativeAOT or complex resources: side-by-side **field completeness**, semantic explanations, warning fidelity and cross-linked addresses against PPEE v2, Malcat, PE-bear, PortEx, LIEF and Peek-a-Bin.
2. ELF with symbols, DWARF, Go runtime metadata and mixed executable/data regions: compare actual recovered metadata against KDE ELF Dissector, dwex, `readelf`, `llvm-dwarfdump`, Ghidra and Rizin.
3. Instrumented ground-truth binaries with known functions, callbacks and vtables: **precision and recall** of disassembly seeds / reachable-code ISA detection; preserve false positives and false negatives, and report time/memory.
4. Browser privacy: distinguish **local file contents** from fetched static WASM/API assets, remote analytics (if any), and optional external links. Verify using browser network traces.
5. Robustness: malformed-file corpus, differential output, mutation tests, supported-version contracts and reproducer links. Resist claims of “100% correct”.

The README should describe the tool itself in the first screen. Link to this landscape report as **further context**, not as the main product pitch.
