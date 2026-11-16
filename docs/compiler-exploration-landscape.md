# Compiler Exploration and Source-to-Assembly Landscape

> **Source survey: 2026-11-15; cross-document review: 2026-11-16.** A curated
> cross-ecosystem inventory of tools connecting source code to generated machine
> assembly, JIT code, compiler IR, bytecode or optimization decisions. This is a *discovery and capability study*,
> not an executed benchmark or a claim that every such tool has been found.
>
> **Corpus ownership:** this is the canonical inventory for **compiler/source-to-code
> exploration**, separate from the [post-build binary-analysis catalog](binary-analysis-landscape.md).
> The [Evaluation](binary-analysis-evaluation.md#evidence-and-claim-records) document defines
> shared evidence types and records comparative results; [Techniques](binary-analysis-techniques.md)
> explains binary-analysis methods. Mentions of binary101/Ghidra here are contextual,
> not additional source-to-assembly inventory entries.

## Scope, terminology, and evidence standard

The central question is: **Given a source fragment or project, what executable code
will a particular compiler, toolchain, configuration, and target produce?**
That covers several non-equivalent workflows:

1. **Ahead-of-time (AOT) code generation:** C/C++/Rust or another source language
   to a compiler's target-assembly text. Text emitted with an assembly-output
   option may differ from bytes later assembled, linked, relocated, and rewritten.
2. **Runtime JIT inspection:** .NET or Java source/bytecode to machine code
   *actually generated for a specific runtime and invocation environment*.
   Tiering, profile-guided optimization (PGO), inlining, and hardware can change it.
3. **Intermediate-representation (IR) exploration:** AST, LLVM IR, Rust MIR,
   .NET IL, JVM bytecode, WebAssembly text, MLIR, SPIR-V, DXIL, or PTX.
   These are informative but not interchangeable with the final native ISA.
4. **Post-build source/disassembly correlation:** A built object or executable
   is disassembled and correlated with source/debug metadata. This may expose
   final linked instructions, but requires a suitable build and debug information.
5. **Shader/GPU code generation:** Shader source to portable GPU IR or
   device-specific instructions. PTX and SPIR-V are *not* equivalent to the
   device's final machine instructions.

A **product**, its **frontend**, its **compiler backend**, and its **upstream**
must not be counted as independent implementations. For example, LLVM Explorer
reuses a WasmBolt-derived compiler runtime; a VS Code view that calls the
Compiler Explorer API is an alternative interface, not a second compiler service.

**Evidence:** apply the [shared evidence and claim standard](binary-analysis-evaluation.md#evidence-and-claim-records). Entries here are mostly **documented**, not `sample-verified`; no common cross-product executions were carried out. Report source date, exact runtime/compiler build and execution environment when available. Missing claims mean **unknown**, never proven absence. The experimental corpus below is proposed, not measured performance data.

**Execution location** is a first-class architectural distinction. Hosted
server-side compilation receives the source sent to its API. In-browser
WebAssembly compilation can keep source processing on the user's machine
after executable assets have been fetched. Local editor/CLI tools use an
installed toolchain. A browser UI alone does *not* imply local compilation.

## Key findings

- [Compiler Explorer (Godbolt)](https://godbolt.org/) is a major reference for
  side-by-side compiler versions, flags, targets and annotated assembly.
  No **comprehensive breadth ranking** or common-corpus quality benchmark
  was performed; other products serve different source/build workflows.
- [LLVM Explorer](https://github.com/afshin/llvm-explorer) and
  [WasmBolt](https://github.com/anutosh491/WasmBolt) demonstrate a materially
  different architecture: C/C++/LLVM work inside the browser using WebAssembly
  toolchains. They share technological lineage, but expose different workflows.
- [SharpLab](https://sharplab.io/) and [DotNetLab](https://github.com/jjonescz/DotNetLab)
  cover managed .NET compilation and JIT outputs; Java HotSpot has a different,
  diagnostic-log-oriented family (JITWatch).
- Real-project and *diff* workflows are served by tools such as
  [cargo-show-asm](https://github.com/pacak/cargo-show-asm),
  [LocalBolt](https://github.com/RonaldMishiev/LocalBolt),
  [asmdiff](https://github.com/rt-rtos/asmdiff), and IDE plugins.
- For GPU output, separate portable shader compilation from final GPU ISA.
  AMD Radeon GPU Analyzer is an important offline specialist.
- **Shader Playground is historical, not a live recommendation.**
  Its author announced a shutdown planned for April 2026, and the GitHub
  repository was archived on 2026-10-06.
  [Closure notice](https://timjones.io/blog/archive/2026/03/18/shutting-down-shader-playground) ·
  [source archive](https://github.com/tgjones/shader-playground).

## 1. Direct source-to-assembly explorers and comparison tools

Each row is one distinct product/interface, not necessarily one unique compiler
engine. “Native assembly” below refers to a target's assembly syntax or
disassembly; **it does not by itself guarantee post-link machine bytes**.

| Tool / primary source | Inputs and characteristic outputs | Execution / interaction model | Distinguishing value and boundary |
|---|---|---|---|
| [**Compiler Explorer / Godbolt**](https://github.com/compiler-explorer/compiler-explorer) · [app](https://godbolt.org/) | C/C++, Rust, Go, D, .NET, Java, Swift and many others; compiler-specific assembly, IR and diagnostic views | Hosted multi-toolchain service; configurable panes, multiple compilers and share links; self-hostable | General reference for compiler/version/flag comparisons, source-to-asm highlighting, libraries and multiple outputs. Supported subviews vary by compiler/language. Hosted compilation transmits submitted source. |
| [**LLVM Explorer**](https://github.com/afshin/llvm-explorer) · [app](https://llvm-explorer.dev/) | C23/C++23, LLVM IR, MLIR; AST, pre/post-optimization IR, CFG/analysis graphs, x86-64/AArch64/Wasm assembly and objects | Standalone browser app plus JupyterLab/JupyterLite integration; compiler runs browser-side | Strong multi-stage pipeline introspection and browser locality. Native-target system headers are limited; packaged WebAssembly toolchain is a different target environment. |
| [**WasmBolt**](https://github.com/anutosh491/WasmBolt) | C23/C++23, LLVM IR and MLIR; Clang AST, IR, LLVM optimizer passes, llc assembly/object, CFG; Wasm linking and selected function execution | Browser-native Clang/LLVM/MLIR modules in Web Workers; terminal, generated-file viewer, optional clangd | Exposes manual LLVM/MLIR tool invocations and build artifacts. WebAssembly execution supports a restricted set of callable interfaces; native x86-64/AArch64 output is inspection-only. |
| [**IRAnatomy**](https://github.com/mooofin/IRAnatomy) | C/C++ through LLVM passes; intermediate snapshots, comparisons, assembly and graphical control flow | Web frontend backed by a compiler server; self-hostable | Useful for tracing a *sequence* of optimization passes. Not equivalent to a no-upload compiler-in-Wasm tool; live public service status not established. |
| [**LocalBolt**](https://github.com/RonaldMishiev/LocalBolt) | Primarily C++ to GCC/Clang assembly, source/assembly view and optional llvm-mca-oriented performance insights | Local terminal UI, installed compilers, live recompilation | Lightweight offline developer workflow, including compilation-database awareness. Young/small project; exact supported compiler-platform matrix untested. |
| [**asmdiff**](https://github.com/rt-rtos/asmdiff) | Source or build outputs to per-function native assembly; compare compilers, flags and revisions | Local Python CLI and build-tool integrations | Assembly **differences** rather than a Godbolt-like editor. Comparison fidelity depends on build context and symbol/disassembly quality. |
| [**Rust Playground**](https://play.rust-lang.org/) · [source](https://github.com/rust-lang/rust-playground) | Rust snippets to assembly, MIR, LLVM IR and other configured outputs | Hosted Rust compiler sandbox, stable/beta/nightly and build modes | Rust-native entry point with little setup. A snippet runner is not a full Cargo workspace with all build dependencies. |
| [**cargo-show-asm**](https://github.com/pacak/cargo-show-asm) | Functions in Cargo projects to native assembly, LLVM IR, MIR and other representations | Local Cargo CLI using the project/toolchain | Important counterpoint to playgrounds: real dependencies, generics and build configuration. Not a hosted visual comparison UI. |
| [**Assembly Explorer (VS Code)**](https://marketplace.visualstudio.com/items?itemName=kuchingneko.assembly-explorer) | C/C++ source to displayed assembly with source correlation | VS Code extension; configurable Compiler Explorer API or local GCC/Clang toolchains | Convenient editor integration. **Remote/API mode** is a Godbolt frontend; **local mode** performs its own toolchain invocation. |
| [**WebAssembly Explorer**](https://mbebenita.github.io/WasmExplorer/) | Historically C/C++ to Wasm text and backend x86 disassembly/assembly inspection | Browser-facing historical Mozilla prototype; target/code-generation pipelines | Useful architectural predecessor; service functionality and maintenance not revalidated for 2026. Treat as historical/uncertain, not a current default. |

### Relationships and possible double-counting

- **LLVM Explorer → WasmBolt runtime:** LLVM Explorer credits a compiler
  runtime adapted from WasmBolt. Separate products with distinct frontends,
  but substantial compiler-engine reuse.
  [LLVM Explorer README](https://github.com/afshin/llvm-explorer) ·
  [WasmBolt README](https://github.com/anutosh491/WasmBolt).
- **Assembly Explorer → Compiler Explorer:** the extension can use Godbolt's
  remote API, or choose local compilation. Count the workflows separately.
- **Compiler Explorer** is also a platform for specialized compilers such as
  shader compilers; it should not be artificially divided into independent
  projects merely because those compilers appear as selectable entries.
- **LocalBolt, asmdiff and cargo-show-asm** require attention to a *real build
  context*. They may answer questions a toy one-file online example cannot.

## 2. Managed runtimes, JIT code and method-focused inspection

.NET IL and JVM bytecode precede native execution. JIT disassembly observed
from a particular run must be labeled with runtime, tier, optimization settings,
target CPU and whether inlining or PGO was active.

| Tool / source | Runtime and output | Workflow | Scope warning |
|---|---|---|---|
| [**SharpLab**](https://github.com/ashmind/SharpLab) · [app](https://sharplab.io/) | C#, F# and VB.NET; IL, JIT assembly and decompiled C# views as supported | Hosted interactive code lab | JIT output is runtime/configuration dependent; not an AOT GCC/Clang analogue. |
| [**DotNetLab**](https://github.com/jjonescz/DotNetLab) · [app](https://lab.razor.fyi/) | .NET/C# and Razor-related experiments; IL, JIT assembly and compilation insights | Browser-oriented, Blazor/WebAssembly/PWA-oriented project | Distinguish browser UI and locally available functionality from how a particular JIT target is generated. Runtime and offline claims need sample/network validation. |
| [**Disasmo**](https://github.com/EgorBo/Disasmo) | .NET JIT-generated assembly, JIT diagnostics and comparisons | Visual Studio extension with local .NET SDK/runtime | Method-focused practical JIT inspection; installed runtime determines the result. |
| [**JetBrains .NET Disassembler**](https://github.com/JetBrains/dotnet-disassembler-plugin) | .NET assembly across JIT/ReadyToRun/NativeAOT configurations, as supported | Rider plugin and local SDK/runtime workflow | An IDE integration, not a separate online compiler backend; feature support depends on versions and configuration. |
| [**BenchmarkDotNet DisassemblyDiagnoser**](https://benchmarkdotnet.org/articles/features/disassembler.html) | Native disassembly and related source/IL information for benchmarked .NET code | Local, execution/benchmark-backed reports | Better for measuring *executed* optimized code than for editing one snippet; supported OS/runtime/architecture combinations vary. |
| [**.NET jitutils**](https://github.com/dotnet/jitutils) | JIT disassembly collections and cross-runtime/change comparisons | Developer/CI command-line toolchain | More suitable for systematic JIT regressions than casual browsing. |
| [**JITWatch**](https://github.com/chriswhocodes/jitwatch) | JVM/HotSpot compilation logs, bytecode, inlining and assembly when emitted | Local JavaFX desktop investigation of actual JIT logs | Requires appropriate log/assembly generation; not arbitrary pasted Java code → assembly with one click. |
| [**JITWatch4i**](https://github.com/JetBrains/jitwatch4i) | JVM JIT events, source/bytecode/native code correlation | IntelliJ-based IDE workflow | Specialized developer view built around HotSpot JIT evidence; depends on diagnostic setup. |

**Do not collapse four .NET concepts:** C# source → IL; IL → JIT native
instructions; C# → ReadyToRun precompiled native code; C# → NativeAOT final
native binary. Tools may support only some of these stages, and their outputs
need not match for the same method.

## 3. GPU, shader and accelerator-oriented tools

| Tool / primary source | Code-generation stages | Useful scenario | Status / limitation |
|---|---|---|---|
| [**AMD Radeon GPU Analyzer (RGA)**](https://github.com/GPUOpen-Tools/radeon_gpu_analyzer) · [site](https://gpuopen.com/rga/) | Supported shader/OpenCL workflows through IR and **AMD GPU ISA** with performance/resource statistics | Compare device-specific generated instructions, resource usage, disassembly and source correlation | Local desktop/CLI specialist; GPU architecture/compiler support is release dependent, not a generic CPU compiler. |
| [**Slang Playground**](https://shader-slang.org/slang-playground/) | Slang and supported shader dialect transformations to targets such as SPIR-V, HLSL, GLSL, Metal, CUDA and WGSL | Explore language lowering and portability | Most listed outputs are source or portable IR, **not final GPU device machine code**. Specific targets may be unavailable in browser builds. |
| [**Shader Playground**](https://github.com/tgjones/shader-playground) | Historically compared HLSL/GLSL shader compilers and multi-stage intermediate output | Historic reference for shader compiler comparison UX | **Discontinued in 2026; repository archived 2026-10-06.** Do not offer the original hosted app as working. [Author announcement](https://timjones.io/blog/archive/2026/03/18/shutting-down-shader-playground). |
| [**NVIDIA CUDA Binary Utilities**](https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html) | Inspect disassembly/SASS in compiled GPU binaries, e.g. nvdisasm and cuobjdump | Distinguish PTX virtual ISA from actual GPU machine code in locally compiled programs | Command-line post-build analysis tools, not an interactive snippet-to-assembly site. |
| [**Compiler Explorer**](https://godbolt.org/) (shader configurations) | Depends on the selected compiler: shader source → IR or ISA | Compare shader toolchains within the general service | A supported target format is not proof of device-specific GPU ISA; inspect individual compiler output. |

**Important:** GPU source → SPIR-V/PTX/DXIL does not imply final ISA
visibility. A report claiming “shows assembly” must name *which* instruction
set and which compiler stage.

## 4. Related tools that should not be mistaken for direct equivalents

The following exist in the same broad educational or code-inspection
ecosystem, but they do not all solve source → machine instructions in a
dedicated way.

| Tool / source | Primary function | Why it is adjacent rather than a direct substitute |
|---|---|---|
| [**Wandbox**](https://wandbox.org/) · [source](https://github.com/melpon/wandbox) | Hosted many-language compiler and execution sandbox | Can sometimes request assembly through command-line compiler flags; no established first-class cross-compiler assembly-correlation workflow comparable to Godbolt. |
| [**Coliru**](https://coliru.stacked-crooked.com/) | Programmable online C/C++ command-line compile/run | A custom compile command may emit assembly, but this is not a dedicated source-to-assembly visualizer; availability unverified. |
| [**C++ Insights**](https://cppinsights.io/) | Clang-based **source-to-source** C++ transformations | Explains template lowering, implicit calls and syntactic transformations; does **not** primarily show native assembly. |
| [**lensm**](https://github.com/loov/lensm) | Go source/binary/assembly navigation | Especially useful on an actual compiled Go program; primarily a post-build navigator, not a version/flag matrix. |
| [**WebAssembly Studio**](https://webassembly.studio/) | Historical Wasm-focused project/editor workflow | Portable WebAssembly build/inspection differs from native ISA comparison; maintenance and hosted availability unverified. |
| [**WasmMC**](https://github.com/WasmMC/wasmmc.github.io) | Browser assembly encoding/decoding | Assembly ↔ bytes, rather than C/C++ source → optimized machine instructions. |
| [**Alive2**](https://alive2.llvm.org/ce/) | LLVM IR translation validation/optimization correctness | Answers whether a transformation preserves behavior; does not primarily display generated target assembly. |
| [**llvm-mca**](https://llvm.org/docs/CommandGuide/llvm-mca.html) | Static throughput/latency modeling on assembly | Consumes assembly and estimates microarchitectural behavior, not an end-to-end source compiler; used by some surrounding tools. |
| [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) and [binary101](https://github.com/Gladskih/binary101) | Inspect **existing binaries** and metadata | Binary → disassembly/analysis. Not source → compiler-produced assembly. The tool categories are complementary. |

### Deliberate exclusions

Plain online runners without demonstrated assembly/IR inspection, generic
disassemblers without source/build integration, emulators, microbenchmarkers
without a code view, text-based assembler tutorials, and generic reverse
engineering suites are **not** counted as direct competitors. Record newly
discovered projects against the taxonomy before adding them; avoid inflating
the count with wrappers around the same compiler engine.

## 5. Architecture and workflow comparison

This table expresses **documented default workflows** rather than a
numerical feature score. An entry of “not established” does not mean “no”.

| Workflow question | Candidates for controlled evaluation | Main qualification |
|---|---|---|
| Compare GCC vs Clang vs MSVC or many versions on a single snippet | Compiler Explorer | Availability differs by compiler/target; hosted service receives source. |
| Explore optimized and unoptimized LLVM IR plus CFG/assembly | LLVM Explorer, WasmBolt, IRAnatomy, Compiler Explorer | Only some expose arbitrary pass pipelines and every intermediate state. |
| Keep C/C++ snippets and compilation local to the browser | LLVM Explorer, WasmBolt | Assets are downloaded; native library/header availability and browser memory are constrained. |
| Run source→assembly comparisons on proprietary local code | LocalBolt, VS Code Assembly Explorer local mode, asmdiff, cargo-show-asm | Local compilers, project setup and security model still need assessment. |
| Compare assembly between actual builds, revisions and flags | asmdiff, cargo-show-asm, .NET jitutils | Compare assembly stages consistently: compiler output vs linked disassembly. |
| Inspect C# JIT native code | SharpLab, DotNetLab, Disasmo, Rider .NET Disassembler | Must identify runtime, JIT tier and architecture. |
| Understand JIT decisions on real Java runs | JITWatch, JITWatch4i | HotSpot logging/assembly plugin setup required. |
| See final device-specific GPU instructions | Radeon GPU Analyzer; CUDA binary utilities for NVIDIA | Shader portable IR alone cannot answer this. |
| Bridge compiled artifacts into file-format analysis | Compiler/toolchain + binary101 | Binary101 should be evaluated on bytes actually emitted; there is no built-in source compiler. |

### Source-to-assembly correlation is not a universal invariant

- Generated instructions are not always assignable 1:1 to source statements.
  Optimization can delete, fold, move, vectorize, or clone code; inlining can
  interleave multiple source functions.
- Textual assembly emitted before linking can hide section layout, relocation
  resolution, thunks, linker-generated code, ICF, LTO/ThinLTO transformations,
  BOLT-style post-link optimization, and instruction encoding choices.
- A local JIT-disassembly view can depend on warmup, PGO, tiers, CPU features,
  devirtualization, and runtime-specific code generation; record those inputs.
- Debug line tables and source-map overlays are evidence for a *relationship*,
  not a proof of perfect instruction attribution.
- Optimization diagnostics, vectorization remarks and llvm-mca estimates help
  explain behavior, but they are not interchangeable with performance measured
  under a real workload.

## 6. Relevance to binary101: opportunities and boundaries

[binary101](https://github.com/Gladskih/binary101) is a **local browser
binary-file inspector**, not an interactive compiler. It analyzes output
artifacts such as ELF, PE/COFF, Mach-O and Wasm, with depth varying by format.
Its control-flow-guided x86/AArch64 ISA analysis and metadata inspection can
answer questions that an assembly text pane alone cannot.

A useful **complementary research path** is:

1. Compile a pinned source input with GCC/Clang/MSVC/Rust/.NET, specific
   optimization flags and target ISA.
2. Capture the textual assembly and optional IR, **and** the produced
   object/executable and linker command, with SHA-256 hashes.
3. Inspect the final artifact in binary101: sections, imports, relocations,
   function seeds, unwind/debug records, instruction-family counts.
4. Reconcile discrepancies between text assembly, linked executable and
   binary101's discovered code range. Record uncertain or omitted regions,
   LTO/linker effects, and false-positive/false-negative function seeds.
5. Compare with independent post-build oracles such as llvm-objdump,
   objdump, dumpbin or platform tooling. Do not equate text assembly directly
   to the final binary without establishing provenance.

**Potential differentiators to test, not promised features:**
- Highlight the difference between **requested ISA** (compiler flags) and
  **observed instruction families** in the finished binary, with clearly
  stated code-coverage limits.
- Cross-link assembly/function observations to PE/ELF metadata: sections,
  relocations, symbols, debug/unwind and runtime-specific tables.
- Compare two builds' *binary-level* instruction mixes and section layouts
  without pretending this is a full function-semantic diff.
- Preserve client-side no-upload file handling; do not suggest embedding an
  external hosted compiler silently into that trust model.

**Avoid a misleading competitive claim.** “Compiler Explorer does not parse
all PE/ELF metadata” and “binary101 does not compile source snippets” are
product-scope distinctions, not defects. A joint workflow can be more useful
than positioning the two as interchangeable.

## 7. Reproducible evaluation protocol and research backlog

A credible “best tool” ranking would require real executions on a fixed
corpus, not README-feature counting. Proposed minimal corpus:

| Fixture | Experimental controls | Ground-truth question |
|---|---|---|
| Tiny C/C++ function with dead-code and constant propagation | GCC/Clang versions; O0/O2/O3; x86-64 | Do source/assembly views faithfully expose removed/reordered instructions? |
| x86-64 intrinsic and auto-vectorization example | -march baseline vs AVX2/AVX-512, target ABI | Which machine ISA classes appear in emitted object and linked binary? |
| C++ translation unit with templates/exceptions and external library | Real include/link setup; debug info; optional LTO | Can it represent nontrivial project settings and code-size impacts? |
| AArch64 target function | Explicit target triple, CPU, compiler version | Does output represent AArch64 target assembly vs host disassembly? |
| Rust generic function in Cargo workspace | rustc channel/profile, target, dependency graph | Can the tool isolate monomorphized functions and MIR/LLVM IR? |
| .NET method with virtual dispatch/loops | Runtime version, JIT tier, PGO, hardware | Are displayed instructions from the specified JIT and tier? |
| Java HotSpot warmed-up method | JVM build, flags, profile/log settings | Can logged inlining/bytecode/native assembly be reproduced? |
| Shader kernel | Compiler backend, shader stage, AMD/NVIDIA GPU target | Is output portable IR, virtual ISA or actual device ISA? |
| Browser-privacy test | DevTools network trace, fresh profile, disconnected re-run | Which source bytes, compiler jobs and tool assets cross the network? |
| Malformed/huge input and compiler timeout | Identical source/error/resource limits | Are diagnostics accurate and does cancellation release resources? |

Capture for each test: source hash, exact compiler/JIT build, target triple and
CPU, SDK and library versions, full command/options, OS/browser/runtime,
generated assembly/IR and binary hashes, source-mapping evidence, elapsed time
and peak resource use, diagnostics, network trace, and sample result.
Use the [common reproducibility ledger schema](binary-analysis-evaluation.md#comparison-results-ledger)
for retained outcomes; this section defines the distinct **source-to-assembly test corpus**.
Do not assign scores before comparable experimental evidence exists.

### Prioritized follow-up checks

1. **Hands-on compare** Compiler Explorer, LLVM Explorer and WasmBolt on one
   identical C++ function: stages, mapping, result stability, executable
   artifact downloads, and local/privacy behavior.
2. **Function-level diff** asmdiff versus compiler output/disassembly from
   two real optimization variants; check the link-stage confounders.
3. **Managed output** SharpLab vs Disasmo/Rider on the same pinned .NET method,
   explicitly matching JIT tier and runtime build.
4. **Real-world local project** cargo-show-asm, LocalBolt and VS Code Assembly
   Explorer: dependencies, compilation databases, accurate source locations.
5. **GPU ISA** verify RGA support for a chosen architecture and whether
   Compiler Explorer's selected shader toolchain exposes corresponding *real*
   GPU machine instructions, rather than only portable IR.
6. **Maintenance checks** re-fetch repo archival, releases, links, runtime
   provenance and new forks; note when a project has merely changed ownership
   or URL rather than disappearing.

## Sources, provenance and maintenance

Sources are linked in the individual rows. Particularly important primary
references:

- [Compiler Explorer source/README](https://github.com/compiler-explorer/compiler-explorer)
  and [service privacy statement](https://godbolt.org/).
- [LLVM Explorer README/runtime documentation](https://github.com/afshin/llvm-explorer),
  [WasmBolt README](https://github.com/anutosh491/WasmBolt),
  [IRAnatomy README](https://github.com/mooofin/IRAnatomy).
- [Rust Playground repository](https://github.com/rust-lang/rust-playground),
  [cargo-show-asm repository](https://github.com/pacak/cargo-show-asm),
  [asmdiff repository](https://github.com/rt-rtos/asmdiff).
- [.NET jitutils](https://github.com/dotnet/jitutils),
  [BenchmarkDotNet disassembler reference](https://benchmarkdotnet.org/articles/features/disassembler.html),
  [JITWatch](https://github.com/chriswhocodes/jitwatch).
- [AMD RGA documentation](https://gpuopen.com/rga/),
  [Slang Playground](https://shader-slang.org/slang-playground/),
  [NVIDIA CUDA binary tools](https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html).
- [Shader Playground shutdown announcement (2026-03-18)](https://timjones.io/blog/archive/2026/03/18/shutting-down-shader-playground)
  and [archived source](https://github.com/tgjones/shader-playground).

**Verification limits (source survey 2026-11-15; editorial review 2026-11-16):** Product descriptions were reviewed against
project websites, primary READMEs or upstream documentation, but individual
compilations, source-line correlations, offline-mode tests, JIT tiers, actual
generated device ISA, and comparable performance measurements were **not**
executed. Precise current version availability and release activity are
not uniformly audited. In particular, do not infer continuous maintenance
from a reachable page or a populated GitHub repository.

**Update discipline:** Search new candidates by
*AOT vs JIT vs GPU vs IR*, and by *hosted vs local browser vs IDE/CLI*;
preserve one canonical row **within this source-to-assembly inventory**;
cross-reference post-build analysis tools instead of importing their entire
catalog; document frontend/upstream relationships; distinguish statements from
observed behavior; use dated archival and shutdown evidence; and record
experimental outcomes under the [shared comparison protocol](binary-analysis-evaluation.md#evidence-and-claim-records)
instead of turning discovery into an unsupported leaderboard.
