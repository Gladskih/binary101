# Native symbol names

ELF dynamic imports/exports, static symbol tables and relocation references decode
Itanium C++, Rust v0 and supported D names. PE imports, delayed imports, exports and
COFF symbol tables decode these grammars plus MSVC C++. COFF objects use the same
symbol-table reader. Decoded names appear alongside the original linker spelling;
hashing, version lookup, relocation identity, sorting and addresses keep the raw name.
PE import labels identify the decoder that succeeded.

Rust and D use `llvm-rust-demangle@0.1.0` and `llvm-dlang-demangle@0.1.0`, with LLVM
23.1.3 inputs pinned by those packages. Browser loaders receive Vite-emitted local
WASM URLs. The build includes the packages' licenses, runtime notices and upstream
pins under `vendor/`. No runtime service or network dependency is introduced.

Each decoder initializes only for its grammar prefix and shares pending parses for
duplicate names. Its caches belong to the analysis, not a process-wide name store.
Invalid/unsupported names remain raw. Initialization, resource and native failures
produce visible warnings once per affected grammar; other grammars remain available.
Opening another file creates fresh decoders. COFF long names must be complete and
NUL-terminated before demangling; malformed strings retain their existing warnings.

## Classification boundaries

- Rust v0 paths identify functions and statics alike. Neither the namespace nor a
  generic function-type argument proves that the symbol denotes data or a function.
  Rust results therefore add presentation, not new ISA code/data or entrypoint evidence.
- Legacy Rust `_ZN...17h...E` retains the existing Itanium presentation path and its
  conservative exclusion from positive Itanium data classification.
- Successful D trees identify basic typed variables and the Initializer, VTable,
  ClassInfo, Interface and ModuleInfo special productions as data. These extend the
  existing exported-data and ELF NOTYPE data exclusions. `_Dmain` and plain artificial
  names ending in `Z` remain unclassified. No classification parses printed text.
- LLVM's D parser does not implement functions, templates, compound types and several
  other productions. Those names remain raw; this integration does not expand LLVM's grammar.
- i386 COFF adds another platform underscore (`__R...`, `__D...`). PE/COFF strips
  just that extra prefix for decoding and retains the original linker spelling.
  ELF continues to use the strict `_R`/`_D` ABI prefixes.

Sources: [Rust RFC 2603](https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html),
[D ABI](https://dlang.org/spec/abi.html#name_mangling),
[pinned LLVM D parser](https://github.com/llvm/llvm-project/blob/0d261d1ca552c95a8f007e061c787ac7132fbcbc/llvm/lib/Demangle/DLangDemangle.cpp),
[Microsoft decorated names](https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names).

## Independent compiler checks

`samples/demangle/` contains small compiler inputs, not handwritten mangled symbols.
The optional external test compares actual ELF/PE/COFF symbol names with `llvm-nm`
and their presentation with independently compiled **unmodified** LLVM parsers.
For the local validation, Rust 1.96.0 emitted v0 COFF objects for x86/x64; Clang
compiled its LLVM IR for ELF. DMD 2.112.0 emitted native Linux ELF and Windows x86/x64
COFF objects with `-betterC`. LLD linked the x64 objects into DLLs with their actual
symbol names exported. All eight cases pass, including D functions remaining raw.
These finite compiler samples are evidence, not coverage of every language production.

Recreate the named files listed in `tests/external/analyzers.rust-dlang-symbols.test.ts`:
compile `rust_sample.rs` as a library with `-C symbol-mangling-version=v0`,
`-C link-dead-code=yes` and `--emit=obj,llvm-ir`; compile `dlang_sample.d` with
`dmd -c -betterC` for each target. Link DLLs with `lld-link /dll /noentry /nodefaultlib`
and `/export:` for each defined `_R`/`_D` name reported by `llvm-nm -P`.
The native oracle executables come from each demangler package's release verification
and accept newline-delimited names, returning `<invalid>` for unsupported input.

On Windows with WSL, set `DEMANGLE_SAMPLES_DIR` to the compiled files' Windows
directory and `LLVM_DEMANGLER_ORACLE_ROOT` to the Linux path containing the sibling
`llvm-rust-demangle` and `llvm-dlang-demangle` repositories. Then run:

```sh
npx tsx --test tests/external/analyzers.rust-dlang-symbols.test.ts
```

Normal unit and browser tests need neither compilers nor external executables.

## Verification and contribution audit

Validated on 2026-10-18 with Windows Node 26.11.1:

- Full lint, strict type checks, build and unit coverage pass.
- Compared with the unchanged starting commit `a33b04bd`, total coverage increases:
  lines/statements 97.58% to 97.61%, branches 89.40% to 89.42%, and functions
  97.41% to 97.45%. The grammar decoder and shared router have 100% coverage.
- All 67 executable mutations in the new decoder/routing modules are detected;
  TypeScript rejects another 93 mutations. Run `npm run test:mutation:symbol-demangle`.
- Thirteen browser checks pass: new Rust/D scenarios plus existing Itanium/MSVC,
  export paging/remount and ELF relocation scenarios. Eight compiler/oracle cases pass.
- The final `CONTRIBUTING.md` audit checks small cohesive modules/functions,
  explicit parameters, no boolean control parameters or argument bags, unchanged raw
  identities, cached duplicate parsing, bounded existing string readers, visible
  failure diagnostics, local WASM assets and complete third-party notice packaging.
  New behavior has direct tests, with missing integration/labels/asset checks observed
  failing before the implementation. No parser or renderer introduces a service dependency.
