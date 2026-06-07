# PE disassembly sample matrix

This directory contains tiny hello-world programs used to generate local PE files for
entrypoint and instruction disassembly work. The point is not to model program logic, but to
produce different compiler frontends, CRT/runtime entry paths, linkers, architectures, and
optimization shapes from the same small source idea.

The build entrypoint is:

```powershell
npm run build:pe-samples
```

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

## Why 204 Variants

The matrix currently attempts 204 variants:

| family | count | source |
|---|---:|---|
| C | 65 | MSVC 10 + clang-cl 12 + MSYS2 UCRT64 GCC 8 + MSYS2 UCRT64 clang 8 + MSYS2 CLANG64 clang 8 + LLVM clang 11 + Zig cc 8 |
| C++ | 65 | Same compiler/linker spread as C |
| Rust | 48 | 6 Windows targets x 3 opt levels x 2 panic strategies, plus x64 target-cpu/LTO variants |
| Go | 6 | 2 architectures x default/noopt, plus `GOAMD64=v3/v4` |
| Zig | 6 | 2 architectures x Debug/ReleaseFast/ReleaseSmall |
| C# | 5 | win-x64 framework-dependent, ReadyToRun, win-x86 self-contained, win-x64/x86 NativeAOT |
| Pascal | 2 | Free Pascal win32 O1/O3 |
| D | 3 | DMD x64 debug, x64 release, x86 MSCOFF release |
| Assembly | 4 | NASM x64/x86 and MASM x64/x86 |
| Total | 204 |  |

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

The .NET ReadyToRun variant is still launched through `HelloCSharp.exe`, but the interesting
ReadyToRun native code is in the adjacent `HelloCSharp.dll` produced by `dotnet publish`.

## Current Machine Result

Measured on the dev machine after a full build to
`%TEMP%\binary101-pe-disassembly-samples-expanded2`:

| metric | value |
|---|---:|
| Attempted variants | 204 |
| Successful PE outputs | 192 |
| Failed variants | 0 |
| Skipped variants | 12 |
| Full build wall-clock time | 41.266 s |
| Successful output bytes | 132,306,257 |
| Successful output size | 126.177 MiB |
| All `.exe` files under output root, including support/intermediate files | 129.230 MiB |
| All `.dll` files under output root, including support/intermediate files | 289.590 MiB |
| Full output directory, including logs, obj, .NET support files | 566.749 MiB |

The 12 skipped variants are Rust `i686-pc-windows-gnu` and `i686-pc-windows-gnullvm` builds.
The Rust standard libraries are installed, but this machine does not currently have
`i686-w64-mingw32-gcc` or `i686-w64-mingw32-clang` plus the matching import libraries in the
local toolchain. The MSVC i686 Rust target does build.

All 192 successful PE outputs were run locally with MSYS2 UCRT64/CLANG64 runtime
directories on `PATH`; all exited with code 0 and printed exactly `Hello, world!`.

## Size Leaders and Notes

Smallest successful output:

| id | size bytes | size KiB | note |
|---|---:|---:|---|
| assembly-nasm-x64-lld | 1,536 | 1.5 | Direct WinAPI NASM x64 linked by `lld-link`, no CRT startup. |

Largest successful output:

| id | size bytes | size KiB | note |
|---|---:|---:|---|
| rust-x64-gnu-o0-panic-unwind | 4,908,772 | 4,793.7 | Rust GNU x64 with std and unwind runtime. |

Interesting size patterns from this run:

- Direct WinAPI assembly outputs stay tiny: 1.5 KiB to 3.0 KiB.
- MSVC and clang-cl C/C++ `/MD` outputs are small because they use the DLL CRT.
- MSVC and clang-cl `/MT` outputs jump to roughly 89 KiB to 215 KiB because they carry a
  static CRT slice.
- Rust thin LTO has a large effect on GNU/gnullvm x64: the GNU output drops from about
  4.8 MiB to about 1.85 MiB, and the gnullvm output drops from about 4.0 MiB to about
  1.8 MiB.
- The `-march`/`-mtune` variants often keep identical file sizes for this tiny program, but
  they still give the disassembler distinct compiler command provenance and may affect code
  shape in startup/runtime paths.
- Rust MSVC targets are around 108.5 KiB to 126.0 KiB, while Rust GNU/gnullvm x64 outputs
  are around 4.0 MiB to 4.8 MiB.
- Go hello-world outputs are about 2.2 MiB to 2.4 MiB; `GOAMD64=v3/v4` is slightly smaller
  than default on this run.
- Zig native release outputs are much smaller than Zig debug outputs: about 397 KiB to
  737.5 KiB versus about 1.8 MiB to 1.9 MiB.
- Zig `c++` outputs are much larger than the MSVC/MSYS2 C++ outputs in this sample set,
  which is useful for disassembly coverage because the runtime shape is visibly different.
  The Zig `cc` CPU variants also visibly move sizes, unlike most MSVC/clang hello-world
  CPU-mode variants here.

## Output Binary Sizes

| id | language | size bytes | size KiB |
|---|---|---:|---:|
| assembly-masm-x64-link | assembly | 2560 | 2.5 |
| assembly-masm-x86-link | assembly | 3072 | 3.0 |
| assembly-nasm-x64-lld | assembly | 1536 | 1.5 |
| assembly-nasm-x86-lld | assembly | 3072 | 3.0 |
| c-clang-cl-x64-o2-md | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-md-flto | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-md-march-x86-64-v2 | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-md-march-x86-64-v3 | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-md-march-znver5 | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-md-mtune-znver5 | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-mt | c | 117248 | 114.5 |
| c-clang-cl-x64-od-md | c | 8704 | 8.5 |
| c-clang-cl-x86-o2-md | c | 7680 | 7.5 |
| c-clang-cl-x86-o2-md-flto | c | 7680 | 7.5 |
| c-clang-cl-x86-o2-mt | c | 91136 | 89.0 |
| c-clang-cl-x86-od-md | c | 7680 | 7.5 |
| c-llvm-clang-msvc-x64-o0 | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-o2 | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-o2-flto | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-o2-march-x86-64-v2 | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-o2-march-x86-64-v3 | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-o2-march-znver5 | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-o2-mtune-znver5 | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x64-os | c | 117248 | 114.5 |
| c-llvm-clang-msvc-x86-o0 | c | 91136 | 89.0 |
| c-llvm-clang-msvc-x86-o2 | c | 91136 | 89.0 |
| c-llvm-clang-msvc-x86-os | c | 91136 | 89.0 |
| c-msvc-x64-o2-md | c | 9728 | 9.5 |
| c-msvc-x64-o2-md-arch-avx2 | c | 9728 | 9.5 |
| c-msvc-x64-o2-md-arch-avx512 | c | 9728 | 9.5 |
| c-msvc-x64-o2-md-ltcg | c | 9728 | 9.5 |
| c-msvc-x64-o2-mt | c | 111104 | 108.5 |
| c-msvc-x64-od-md | c | 9728 | 9.5 |
| c-msvc-x86-o2-md | c | 8192 | 8.0 |
| c-msvc-x86-o2-md-ltcg | c | 8192 | 8.0 |
| c-msvc-x86-o2-mt | c | 92160 | 90.0 |
| c-msvc-x86-od-md | c | 8192 | 8.0 |
| c-msys-clang64-x64-o0 | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2 | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2-flto | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2-march-x86-64-v2 | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2-march-x86-64-v3 | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2-march-znver5 | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2-mtune-znver5 | c | 84992 | 83.0 |
| c-msys-clang64-x64-os | c | 84992 | 83.0 |
| c-msys-ucrt64-clang-x64-o0 | c | 133993 | 130.9 |
| c-msys-ucrt64-clang-x64-o2 | c | 133993 | 130.9 |
| c-msys-ucrt64-clang-x64-o2-flto | c | 109568 | 107.0 |
| c-msys-ucrt64-clang-x64-o2-march-x86-64-v2 | c | 133993 | 130.9 |
| c-msys-ucrt64-clang-x64-o2-march-x86-64-v3 | c | 133993 | 130.9 |
| c-msys-ucrt64-clang-x64-o2-march-znver5 | c | 133993 | 130.9 |
| c-msys-ucrt64-clang-x64-o2-mtune-znver5 | c | 133993 | 130.9 |
| c-msys-ucrt64-clang-x64-os | c | 133993 | 130.9 |
| c-msys-ucrt64-x64-o0 | c | 135583 | 132.4 |
| c-msys-ucrt64-x64-o2 | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-o2-flto | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-o2-march-x86-64-v2 | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-o2-march-x86-64-v3 | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-o2-march-znver5 | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-o2-mtune-znver5 | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-os | c | 135107 | 131.9 |
| c-zig-cc-x64-o0 | c | 188416 | 184.0 |
| c-zig-cc-x64-o2 | c | 188416 | 184.0 |
| c-zig-cc-x64-o2-march-x86-64-v2 | c | 186880 | 182.5 |
| c-zig-cc-x64-o2-march-x86-64-v3 | c | 187904 | 183.5 |
| c-zig-cc-x64-o2-march-znver5 | c | 190976 | 186.5 |
| c-zig-cc-x64-o2-mtune-znver5 | c | 190976 | 186.5 |
| c-zig-cc-x86-o0 | c | 241664 | 236.0 |
| c-zig-cc-x86-o2 | c | 241152 | 235.5 |
| cpp-clang-cl-x64-o2-md | cpp | 10240 | 10.0 |
| cpp-clang-cl-x64-o2-md-flto | cpp | 9728 | 9.5 |
| cpp-clang-cl-x64-o2-md-march-x86-64-v2 | cpp | 10240 | 10.0 |
| cpp-clang-cl-x64-o2-md-march-x86-64-v3 | cpp | 10240 | 10.0 |
| cpp-clang-cl-x64-o2-md-march-znver5 | cpp | 10240 | 10.0 |
| cpp-clang-cl-x64-o2-md-mtune-znver5 | cpp | 10240 | 10.0 |
| cpp-clang-cl-x64-o2-mt | cpp | 220672 | 215.5 |
| cpp-clang-cl-x64-od-md | cpp | 11776 | 11.5 |
| cpp-clang-cl-x86-o2-md | cpp | 8704 | 8.5 |
| cpp-clang-cl-x86-o2-md-flto | cpp | 8704 | 8.5 |
| cpp-clang-cl-x86-o2-mt | cpp | 175616 | 171.5 |
| cpp-clang-cl-x86-od-md | cpp | 10240 | 10.0 |
| cpp-llvm-clang-msvc-x64-o0 | cpp | 229888 | 224.5 |
| cpp-llvm-clang-msvc-x64-o2 | cpp | 224768 | 219.5 |
| cpp-llvm-clang-msvc-x64-o2-flto | cpp | 224768 | 219.5 |
| cpp-llvm-clang-msvc-x64-o2-march-x86-64-v2 | cpp | 224768 | 219.5 |
| cpp-llvm-clang-msvc-x64-o2-march-x86-64-v3 | cpp | 224768 | 219.5 |
| cpp-llvm-clang-msvc-x64-o2-march-znver5 | cpp | 224768 | 219.5 |
| cpp-llvm-clang-msvc-x64-o2-mtune-znver5 | cpp | 224768 | 219.5 |
| cpp-llvm-clang-msvc-x64-os | cpp | 223744 | 218.5 |
| cpp-llvm-clang-msvc-x86-o0 | cpp | 184832 | 180.5 |
| cpp-llvm-clang-msvc-x86-o2 | cpp | 179200 | 175.0 |
| cpp-llvm-clang-msvc-x86-os | cpp | 178176 | 174.0 |
| cpp-msvc-x64-o2-md | cpp | 10752 | 10.5 |
| cpp-msvc-x64-o2-md-arch-avx2 | cpp | 10752 | 10.5 |
| cpp-msvc-x64-o2-md-arch-avx512 | cpp | 10752 | 10.5 |
| cpp-msvc-x64-o2-md-ltcg | cpp | 10752 | 10.5 |
| cpp-msvc-x64-o2-mt | cpp | 213504 | 208.5 |
| cpp-msvc-x64-od-md | cpp | 12288 | 12.0 |
| cpp-msvc-x86-o2-md | cpp | 10240 | 10.0 |
| cpp-msvc-x86-o2-md-ltcg | cpp | 9728 | 9.5 |
| cpp-msvc-x86-o2-mt | cpp | 175616 | 171.5 |
| cpp-msvc-x86-od-md | cpp | 11264 | 11.0 |
| cpp-msys-clang64-x64-o0 | cpp | 95232 | 93.0 |
| cpp-msys-clang64-x64-o2 | cpp | 88576 | 86.5 |
| cpp-msys-clang64-x64-o2-flto | cpp | 88064 | 86.0 |
| cpp-msys-clang64-x64-o2-march-x86-64-v2 | cpp | 88576 | 86.5 |
| cpp-msys-clang64-x64-o2-march-x86-64-v3 | cpp | 88576 | 86.5 |
| cpp-msys-clang64-x64-o2-march-znver5 | cpp | 88576 | 86.5 |
| cpp-msys-clang64-x64-o2-mtune-znver5 | cpp | 88576 | 86.5 |
| cpp-msys-clang64-x64-os | cpp | 90624 | 88.5 |
| cpp-msys-ucrt64-clang-x64-o0 | cpp | 134110 | 131.0 |
| cpp-msys-ucrt64-clang-x64-o2 | cpp | 134154 | 131.0 |
| cpp-msys-ucrt64-clang-x64-o2-flto | cpp | 109568 | 107.0 |
| cpp-msys-ucrt64-clang-x64-o2-march-x86-64-v2 | cpp | 134154 | 131.0 |
| cpp-msys-ucrt64-clang-x64-o2-march-x86-64-v3 | cpp | 134154 | 131.0 |
| cpp-msys-ucrt64-clang-x64-o2-march-znver5 | cpp | 134154 | 131.0 |
| cpp-msys-ucrt64-clang-x64-o2-mtune-znver5 | cpp | 134154 | 131.0 |
| cpp-msys-ucrt64-clang-x64-os | cpp | 134154 | 131.0 |
| cpp-msys-ucrt64-x64-o0 | cpp | 136212 | 133.0 |
| cpp-msys-ucrt64-x64-o2 | cpp | 136804 | 133.6 |
| cpp-msys-ucrt64-x64-o2-flto | cpp | 137300 | 134.1 |
| cpp-msys-ucrt64-x64-o2-march-x86-64-v2 | cpp | 136804 | 133.6 |
| cpp-msys-ucrt64-x64-o2-march-x86-64-v3 | cpp | 136804 | 133.6 |
| cpp-msys-ucrt64-x64-o2-march-znver5 | cpp | 136804 | 133.6 |
| cpp-msys-ucrt64-x64-o2-mtune-znver5 | cpp | 136804 | 133.6 |
| cpp-msys-ucrt64-x64-os | cpp | 136804 | 133.6 |
| cpp-zig-cc-x64-o0 | cpp | 1456640 | 1422.5 |
| cpp-zig-cc-x64-o2 | cpp | 850432 | 830.5 |
| cpp-zig-cc-x64-o2-march-x86-64-v2 | cpp | 848384 | 828.5 |
| cpp-zig-cc-x64-o2-march-x86-64-v3 | cpp | 859136 | 839.0 |
| cpp-zig-cc-x64-o2-march-znver5 | cpp | 870400 | 850.0 |
| cpp-zig-cc-x64-o2-mtune-znver5 | cpp | 870400 | 850.0 |
| cpp-zig-cc-x86-o0 | cpp | 1427456 | 1394.0 |
| cpp-zig-cc-x86-o2 | cpp | 853504 | 833.5 |
| csharp-framework-win-x64-release | csharp | 162304 | 158.5 |
| csharp-nativeaot-win-x64-release | csharp | 1105408 | 1079.5 |
| csharp-nativeaot-win-x86-release | csharp | 933888 | 912.0 |
| csharp-readytorun-win-x64-release | csharp | 162304 | 158.5 |
| csharp-selfcontained-win-x86-release | csharp | 131584 | 128.5 |
| d-dmd-x64-debug | d | 590336 | 576.5 |
| d-dmd-x64-release | d | 588800 | 575.0 |
| d-dmd-x86-mscoff-release | d | 505856 | 494.0 |
| go-windows-386-default | go | 2309120 | 2255.0 |
| go-windows-386-noopt | go | 2238464 | 2186.0 |
| go-windows-amd64-default | go | 2457088 | 2399.5 |
| go-windows-amd64-goamd64-v3 | go | 2447872 | 2390.5 |
| go-windows-amd64-goamd64-v4 | go | 2447872 | 2390.5 |
| go-windows-amd64-noopt | go | 2397184 | 2341.0 |
| pascal-fpc-win32-o1 | pascal | 34304 | 33.5 |
| pascal-fpc-win32-o3 | pascal | 34304 | 33.5 |
| rust-x64-gnullvm-o0-panic-abort | rust | 4154880 | 4057.5 |
| rust-x64-gnullvm-o0-panic-unwind | rust | 4162560 | 4065.0 |
| rust-x64-gnullvm-o3-panic-abort | rust | 4154368 | 4057.0 |
| rust-x64-gnullvm-o3-panic-abort-lto-thin | rust | 1845760 | 1802.5 |
| rust-x64-gnullvm-o3-panic-abort-target-cpu-native | rust | 4154368 | 4057.0 |
| rust-x64-gnullvm-o3-panic-abort-target-cpu-x86-64-v2 | rust | 4154368 | 4057.0 |
| rust-x64-gnullvm-o3-panic-abort-target-cpu-x86-64-v3 | rust | 4154368 | 4057.0 |
| rust-x64-gnullvm-o3-panic-unwind | rust | 4162048 | 4064.5 |
| rust-x64-gnullvm-oz-panic-abort | rust | 4154368 | 4057.0 |
| rust-x64-gnullvm-oz-panic-unwind | rust | 4162048 | 4064.5 |
| rust-x64-gnu-o0-panic-abort | rust | 4901523 | 4786.6 |
| rust-x64-gnu-o0-panic-unwind | rust | 4908772 | 4793.7 |
| rust-x64-gnu-o3-panic-abort | rust | 4901133 | 4786.3 |
| rust-x64-gnu-o3-panic-abort-lto-thin | rust | 1894106 | 1849.7 |
| rust-x64-gnu-o3-panic-abort-target-cpu-native | rust | 4901133 | 4786.3 |
| rust-x64-gnu-o3-panic-abort-target-cpu-x86-64-v2 | rust | 4901133 | 4786.3 |
| rust-x64-gnu-o3-panic-abort-target-cpu-x86-64-v3 | rust | 4901133 | 4786.3 |
| rust-x64-gnu-o3-panic-unwind | rust | 4908364 | 4793.3 |
| rust-x64-gnu-oz-panic-abort | rust | 4901194 | 4786.3 |
| rust-x64-gnu-oz-panic-unwind | rust | 4908425 | 4793.4 |
| rust-x64-msvc-o0-panic-abort | rust | 126464 | 123.5 |
| rust-x64-msvc-o0-panic-unwind | rust | 129024 | 126.0 |
| rust-x64-msvc-o3-panic-abort | rust | 123904 | 121.0 |
| rust-x64-msvc-o3-panic-abort-lto-thin | rust | 122368 | 119.5 |
| rust-x64-msvc-o3-panic-abort-target-cpu-native | rust | 123904 | 121.0 |
| rust-x64-msvc-o3-panic-abort-target-cpu-x86-64-v2 | rust | 123904 | 121.0 |
| rust-x64-msvc-o3-panic-abort-target-cpu-x86-64-v3 | rust | 123904 | 121.0 |
| rust-x64-msvc-o3-panic-unwind | rust | 125440 | 122.5 |
| rust-x64-msvc-oz-panic-abort | rust | 123904 | 121.0 |
| rust-x64-msvc-oz-panic-unwind | rust | 125440 | 122.5 |
| rust-x86-msvc-o0-panic-abort | rust | 111616 | 109.0 |
| rust-x86-msvc-o0-panic-unwind | rust | 113664 | 111.0 |
| rust-x86-msvc-o3-panic-abort | rust | 111104 | 108.5 |
| rust-x86-msvc-o3-panic-unwind | rust | 112640 | 110.0 |
| rust-x86-msvc-oz-panic-abort | rust | 111104 | 108.5 |
| rust-x86-msvc-oz-panic-unwind | rust | 112640 | 110.0 |
| zig-x64-debug | zig | 1830400 | 1787.5 |
| zig-x64-releasefast | zig | 754688 | 737.0 |
| zig-x64-releasesmall | zig | 433152 | 423.0 |
| zig-x86-debug | zig | 1944064 | 1898.5 |
| zig-x86-releasefast | zig | 755200 | 737.5 |
| zig-x86-releasesmall | zig | 406528 | 397.0 |
