# PE disassembly sample matrix

This directory contains tiny hello-world programs used to generate local PE files for
entrypoint and instruction disassembly work. The point is not to model program logic, but to
produce different compiler frontends, CRT/runtime entry paths, linkers, architectures, and
optimization shapes from the same small source idea.

The build entrypoint is:

```powershell
npm run build:pe-samples
```

The implementation lives under `scripts/pe-disassembly-samples/`.

By default it writes generated files to:

```text
%TEMP%\binary101-pe-disassembly-samples\
```

That output directory contains `commands.txt`, `summary.json`, `summary.md`, per-variant
`build.log.md` files, and successful `.exe` outputs. The script also supports `--dry-run`,
`--filter`, `--jobs`, and `--output`.

## Local Toolchain Setup

This is the local compiler set used for the current sample matrix. Most commands are run from
PowerShell:

```powershell
winget install -e --id LLVM.LLVM
winget install --id Microsoft.VisualStudio.BuildTools -e `
  --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install Microsoft.DotNet.SDK.10
winget install Rustlang.Rustup
rustup target add i686-pc-windows-gnu
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
rustup target add x86_64-pc-windows-gnullvm
rustup target add i686-pc-windows-gnullvm
winget install GoLang.Go
winget install zig.zig
winget install MSYS2.MSYS2
winget install -e --id NASM.NASM
winget install -e --id FreePascal.FreePascalCompiler
winget install -e --id Dlang.DMD
```

Notes:

- The Visual Studio Build Tools install is intentionally the modern VCTools workload only.
- MASM is provided by the Visual Studio VCTools install.
- FASM is not part of this baseline because the winget package
  had a hash issue during setup.
- Only DMD is installed for D samples for now while there are two more options.
- TinyCC may be useful later as an extra small-C-runtime comparison point.

MSYS2 needs package installation from the matching MSYS2 shell, not plain PowerShell. First
update the package database from an `MSYS2 UCRT64` shell,
then restart that shell if pacman asks for it and update again:

```bash
pacman -Syu
```

From `MSYS2 UCRT64`:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-clang
pacman -S mingw-w64-ucrt-x86_64-lld
```

From the MSYS2 CLANG64 shell:

```bash
pacman -S mingw-w64-clang-x86_64-clang
pacman -S mingw-w64-clang-x86_64-lld
```

This baseline deliberately installs only the modern x64 MSYS2 compiler families. Because of
that, Rust `i686-pc-windows-gnu` and `i686-pc-windows-gnullvm` variants are skipped unless
matching `i686-w64-mingw32-gcc` / `i686-w64-mingw32-clang` linker toolchains and import
libraries are added later.

## Why 205 Variants

The matrix currently attempts 205 variants:

| family | count | source |
|---|---:|---|
| C | 65 | MSVC 10 + clang-cl 12 + MSYS2 UCRT64 GCC 8 + MSYS2 UCRT64 clang 8 + MSYS2 CLANG64 clang 8 + LLVM clang 11 + Zig cc 8 |
| C++ | 65 | Same compiler/linker spread as C |
| Rust | 48 | 6 Windows targets x 3 opt levels x 2 panic strategies, plus x64 target-cpu/LTO variants |
| Go | 6 | 2 architectures x default/noopt, plus `GOAMD64=v3/v4` |
| Zig | 6 | 2 architectures x Debug/ReleaseFast/ReleaseSmall |
| C# | 6 | win-x64 framework-dependent, ReadyToRun single-file, ReadyToRun self-contained single-file, win-x86 self-contained, win-x64/x86 NativeAOT |
| Pascal | 2 | Free Pascal win32 O1/O3 |
| D | 3 | DMD x64 debug, x64 release, x86 MSCOFF release |
| Assembly | 4 | NASM x64/x86 and MASM x64/x86 |
| Total | 205 |  |

The C and C++ rows use the same 65-way compiler spread:

| compiler family | count | breakdown |
|---|---:|---|
| MSVC `cl.exe` | 10 | x64/x86 x `Od /MD`, `O2 /MD`, `O2 /MT`; x64/x86 `O2 /MD /GL /LTCG`; x64 `O2 /MD /arch:AVX2/AVX512` |
| LLVM `clang-cl` | 12 | x64/x86 x `Od /MD`, `O2 /MD`, `O2 /MT`; x64/x86 `O2 /MD -flto`; x64 `-march=x86-64-v2/v3`, `-mtune=znver5`, `-march=znver5` |
| MSYS2 UCRT64 GCC | 8 | x64 x `O0`, `O2`, `Os`, `O2 -flto`, `O2 -march=x86-64-v2/v3`, `O2 -mtune=znver5`, `O2 -march=znver5` |
| MSYS2 UCRT64 clang | 8 | Same x64 spread as UCRT64 GCC, but using `clang`/`clang++` and `lld` for LTO |
| MSYS2 CLANG64 clang | 8 | Same x64 clang spread from the CLANG64 runtime family |
| LLVM `clang` / `clang++` | 11 | gcc-style driver under `vcvarsall`: x64/x86 x `O0`, `O2`, `Os`; x64 `O2 -flto`; x64 CPU/tune variants |
| Zig `cc` / `c++` | 8 | x64/x86 x `O0`, `O2`; x64 `-march=x86_64_v2/v3`, `-mtune=znver5`, `-march=znver5` |

Options were chosen for machine-code diversity: frontend, backend, linker, runtime model,
architecture, optimization level, and panic/runtime strategy. Options that mostly change PE
metadata without adding useful disassembly diversity are intentionally not multiplied here.

For CPU options, `-march` changes the target CPU/ISA contract and can allow instructions that
older CPUs do not have. `-mtune` keeps the ISA baseline but changes the optimizer cost model
and scheduling choices. On this machine `native` maps to `znver5`, so the matrix uses explicit
`znver5` labels where the compiler accepts them. Zig uses underscore CPU spellings such as
`x86_64_v3`, while GCC/Clang/Rust use hyphenated names such as `x86-64-v3`.

PGO is intentionally not included yet. A useful PGO sample needs an instrumented build, a
profile run, and a second optimized build; for hello-world it mostly measures the automation
rather than producing a meaningfully different disassembly target.

## Automation Notes

The build script discovers toolchains from both `PATH` and common local install locations:
LLVM `clang`, `clang++`, `clang-cl`, Visual Studio Build Tools via `vswhere`, Rust, Go, Zig,
MSYS2 UCRT64/CLANG64, NASM, Free Pascal, DMD, and .NET.

Visual Studio, MASM, `clang-cl`, and standalone LLVM `clang`/`clang++` MSVC-target builds are
wrapped through `vcvarsall.bat` so a normal PowerShell can build MSVC-family samples. MSYS2
directories are prepended to `PATH` where their runtime DLLs or GNU-style linkers are needed.
`clang-cl` and gcc-style LLVM clang receive explicit Windows targets so x86 builds do not
accidentally compile as the host x64 target.

The script records every command and does not stop the whole matrix when a toolchain branch is
missing. Variants with known missing prerequisites are marked as skipped; actual compiler or
linker failures are recorded as failures with stdout/stderr in the variant log.

The .NET ReadyToRun samples are intentionally single-file shapes only: framework-dependent
single-file apphost and self-contained single-file apphost. Both keep the publish output to
one `.exe`, but the entrypoint is still the .NET apphost/bootstrap rather than the managed
`Main` body.

Primary PE outputs are compiled with toolchain-native symbol stripping where the toolchain
supports it: Rust uses `-C strip=symbols`, Go uses `-ldflags=-s -w`, Zig native uses
`-fstrip`, and gcc-style native/linker frontends use `-s`. After each successful compile, the
build pipeline validates that the primary `.exe` has no COFF symbol records. Adjacent `.pdb`
files may still be emitted by toolchains that keep debug information outside the executable.
Go is the intentionally authentic edge case in the current matrix: its internal Windows linker
documents `-s` as disabling the symbol table and produces `NumberOfSymbols=0`, but still may
leave a nonzero `PointerToSymbolTable` to an empty COFF string-table area. The pipeline logs
that condition and leaves the Go executable untouched rather than replacing the internal Go
linker with an external linker.

## Current Machine Result

Measured on the dev machine after a full build to
`%TEMP%\binary101-pe-disassembly-samples-stripped-final`:

| metric | value |
|---|---:|
| Attempted variants | 205 |
| Successful PE outputs | 193 |
| Failed variants | 0 |
| Skipped variants | 12 |
| Full build wall-clock time | 33.965 s |
| Successful output bytes | 124,930,533 |
| Successful output size | 119.143 MiB |
| All `.exe` files under output root, including support/intermediate files | 132.083 MiB |
| All `.dll` files under output root, including support/intermediate files | 435.630 MiB |
| Full output directory, including logs, obj, .NET support files | 622.450 MiB |

The 12 skipped variants are Rust `i686-pc-windows-gnu` and `i686-pc-windows-gnullvm` builds.
The Rust standard libraries are installed, but this machine does not currently have
`i686-w64-mingw32-gcc` or `i686-w64-mingw32-clang` plus the matching import libraries in the
local toolchain. The MSVC i686 Rust target does build.

All 193 successful PE outputs were run locally with MSYS2 UCRT64/CLANG64 runtime
directories on `PATH`; all exited with code 0 and printed exactly `Hello, world!`. An
independent PE header check also confirmed `NumberOfSymbols=0` for every successful primary
output; the only nonzero `PointerToSymbolTable` values are the six authentic Go internal-link
outputs with zero COFF symbol records.

## Size Leaders and Notes

Smallest successful output:

| id | size bytes | size KiB | note |
|---|---:|---:|---|
| assembly-nasm-x64-lld | 1,536 | 1.5 | Direct WinAPI NASM x64 linked by `lld-link`, no CRT startup. |

Largest successful output:

| id | size bytes | size KiB | note |
|---|---:|---:|---|
| csharp-readytorun-selfcontained-singlefile-win-x64-release | 83,176,755 | 81,227.3 | .NET ReadyToRun self-contained single-file bundle; by far the largest PE output in this run. |

Interesting size patterns from this run:

- Direct WinAPI assembly outputs stay tiny: 1.5 KiB to 3.0 KiB.
- .NET ReadyToRun single-file is possible: the framework-dependent variant is about 176.7 KiB,
  while the self-contained variant jumps to about 79.3 MiB because it bundles the runtime.
- MSVC and clang-cl C/C++ `/MD` outputs are small because they use the DLL CRT.
- MSVC and clang-cl `/MT` outputs jump to roughly 89 KiB to 215 KiB because they carry a
  static CRT slice.
- Rust thin LTO remains visible after stripping: the x64 GNU output drops to about 269.5 KiB,
  and the x64 gnullvm output drops to about 257.5 KiB.
- The `-march`/`-mtune` variants often keep identical file sizes for this tiny program, but
  they still give the disassembler distinct compiler command provenance and may affect code
  shape in startup/runtime paths.
- Rust MSVC targets are around 108.5 KiB to 126.0 KiB, while Rust GNU/gnullvm x64 outputs
  are around 257.5 KiB to 816.5 KiB after stripping.
- Go hello-world outputs are about 1.5 MiB to 1.7 MiB after `-ldflags=-s -w`.
- Zig native release outputs are much smaller than Zig debug outputs: about 397 KiB to
  737.5 KiB versus about 1.1 MiB.
- Zig `c++` outputs are much larger than the MSVC/MSYS2 C++ outputs in this sample set,
  which is useful for disassembly coverage because the runtime shape is visibly different.
  The Zig `cc` CPU variants also visibly move sizes, unlike most MSVC/clang hello-world
  CPU-mode variants here.

## Output Binary Sizes

The detailed size table is generated separately in `BINARY-SIZES.md` from a build
`summary.json`. The build pipeline validates that primary PE outputs do not contain COFF
symbol records; the table generator only formats those already-validated results into
columns.

Regenerate it with:

```powershell
npm run build:pe-samples -- `
  --output $env:TEMP\binary101-pe-disassembly-samples `
  --size-table samples\pe-disassembly\BINARY-SIZES.md
```
