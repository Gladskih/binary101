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
- It could be interesting to add TinyC to the list too

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

## Why 102 Variants

The matrix currently attempts 102 variants:

| family | count | source |
|---|---:|---|
| C | 22 | MSVC 6 + clang-cl 6 + MSYS2 UCRT64 3 + MSYS2 CLANG64 3 + Zig cc 4 |
| C++ | 22 | Same compiler/linker spread as C |
| Rust | 36 | 6 Windows targets x 3 opt levels x 2 panic strategies |
| Go | 4 | 2 architectures x default/noopt |
| Zig | 6 | 2 architectures x Debug/ReleaseFast/ReleaseSmall |
| C# | 3 | win-x64 framework-dependent, win-x86 self-contained, win-x64 NativeAOT |
| Pascal | 2 | Free Pascal win32 O1/O3 |
| D | 3 | DMD x64 debug, x64 release, x86 MSCOFF release |
| Assembly | 4 | NASM x64/x86 and MASM x64/x86 |
| Total | 102 |  |

The C and C++ rows use the same 22-way compiler spread:

| compiler family | count | breakdown |
|---|---:|---|
| MSVC `cl.exe` | 6 | x64/x86 x `Od /MD`, `O2 /MD`, `O2 /MT` |
| LLVM `clang-cl` | 6 | x64/x86 x `Od /MD`, `O2 /MD`, `O2 /MT` |
| MSYS2 UCRT64 GCC | 3 | x64 x `O0`, `O2`, `Os` |
| MSYS2 CLANG64 clang | 3 | x64 x `O0`, `O2`, `Os` |
| Zig `cc` / `c++` | 4 | x64/x86 x `O0`, `O2` |

Options were chosen for machine-code diversity: frontend, backend, linker, runtime model,
architecture, optimization level, and panic/runtime strategy. Options that mostly change PE
metadata without adding useful disassembly diversity are intentionally not multiplied here.

## Automation Notes

The build script discovers toolchains from both `PATH` and common local install locations:
LLVM, Visual Studio Build Tools via `vswhere`, Rust, Go, Zig, MSYS2 UCRT64/CLANG64, NASM,
Free Pascal, DMD, and .NET.

Visual Studio and MASM builds are wrapped through `vcvarsall.bat` so a normal PowerShell can
build MSVC-family samples. MSYS2 directories are prepended to `PATH` where their runtime DLLs
or GNU-style linkers are needed. `clang-cl` receives an explicit Windows target so x86 builds
do not accidentally compile as the host x64 target.

The script records every command and does not stop the whole matrix when a toolchain branch is
missing. Variants with known missing prerequisites are marked as skipped; actual compiler or
linker failures are recorded as failures with stdout/stderr in the variant log.

## Current Machine Result

Measured on dev machine after a full default build:

| metric | value |
|---|---:|
| Attempted variants | 102 |
| Successful `.exe` outputs | 90 |
| Failed variants | 0 |
| Skipped variants | 12 |
| Full build wall-clock time | 14.519 s |
| Successful output `.exe` bytes | 82,639,524 |
| Successful output `.exe` size | 78.811 MiB |
| All `.exe` files under output root, including support/intermediate files | 80.607 MiB |
| Full output directory, including logs, obj, .NET support files | 372.336 MiB |

The 12 skipped variants are Rust `i686-pc-windows-gnu` and `i686-pc-windows-gnullvm` builds.
The Rust standard libraries are installed, but this machine does not currently have
`i686-w64-mingw32-gcc` or `i686-w64-mingw32-clang` plus the matching import libraries in the
local toolchain. The MSVC i686 Rust target does build.

All 90 successful `.exe` outputs were run locally with MSYS2 UCRT64/CLANG64 runtime
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
- Rust MSVC targets are around 108.5 KiB to 126.0 KiB, while Rust GNU/gnullvm x64 outputs
  are around 4.0 MiB to 4.8 MiB.
- Go hello-world outputs are about 2.2 MiB to 2.4 MiB.
- Zig native release outputs are much smaller than Zig debug outputs: about 397 KiB to
  737.5 KiB versus about 1.8 MiB to 1.9 MiB.
- Zig `c++` outputs are much larger than the MSVC/MSYS2 C++ outputs in this sample set,
  which is useful for disassembly coverage because the runtime shape is visibly different.

## Output Binary Sizes

| id | language | size bytes | size KiB |
|---|---|---:|---:|
| c-msvc-x64-od-md | c | 9728 | 9.5 |
| c-msvc-x64-o2-md | c | 9728 | 9.5 |
| c-msvc-x64-o2-mt | c | 111104 | 108.5 |
| c-msvc-x86-od-md | c | 8192 | 8.0 |
| c-msvc-x86-o2-md | c | 8192 | 8.0 |
| c-msvc-x86-o2-mt | c | 92160 | 90.0 |
| c-clang-cl-x64-od-md | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-md | c | 8704 | 8.5 |
| c-clang-cl-x64-o2-mt | c | 117248 | 114.5 |
| c-clang-cl-x86-od-md | c | 7680 | 7.5 |
| c-clang-cl-x86-o2-md | c | 7680 | 7.5 |
| c-clang-cl-x86-o2-mt | c | 91136 | 89.0 |
| c-msys-ucrt64-x64-o0 | c | 135583 | 132.4 |
| c-msys-ucrt64-x64-o2 | c | 135107 | 131.9 |
| c-msys-ucrt64-x64-os | c | 135107 | 131.9 |
| c-msys-clang64-x64-o0 | c | 84992 | 83.0 |
| c-msys-clang64-x64-o2 | c | 84992 | 83.0 |
| c-msys-clang64-x64-os | c | 84992 | 83.0 |
| c-zig-cc-x64-o0 | c | 188416 | 184.0 |
| c-zig-cc-x64-o2 | c | 188416 | 184.0 |
| c-zig-cc-x86-o0 | c | 241664 | 236.0 |
| c-zig-cc-x86-o2 | c | 241152 | 235.5 |
| cpp-msvc-x64-od-md | cpp | 12288 | 12.0 |
| cpp-msvc-x64-o2-md | cpp | 10752 | 10.5 |
| cpp-msvc-x64-o2-mt | cpp | 213504 | 208.5 |
| cpp-msvc-x86-od-md | cpp | 11264 | 11.0 |
| cpp-msvc-x86-o2-md | cpp | 10240 | 10.0 |
| cpp-msvc-x86-o2-mt | cpp | 175616 | 171.5 |
| cpp-clang-cl-x64-od-md | cpp | 11776 | 11.5 |
| cpp-clang-cl-x64-o2-md | cpp | 10240 | 10.0 |
| cpp-clang-cl-x64-o2-mt | cpp | 220672 | 215.5 |
| cpp-clang-cl-x86-od-md | cpp | 10240 | 10.0 |
| cpp-clang-cl-x86-o2-md | cpp | 8704 | 8.5 |
| cpp-clang-cl-x86-o2-mt | cpp | 175616 | 171.5 |
| cpp-msys-ucrt64-x64-o0 | cpp | 136212 | 133.0 |
| cpp-msys-ucrt64-x64-o2 | cpp | 136804 | 133.6 |
| cpp-msys-ucrt64-x64-os | cpp | 136804 | 133.6 |
| cpp-msys-clang64-x64-o0 | cpp | 95232 | 93.0 |
| cpp-msys-clang64-x64-o2 | cpp | 88576 | 86.5 |
| cpp-msys-clang64-x64-os | cpp | 90624 | 88.5 |
| cpp-zig-cc-x64-o0 | cpp | 1456640 | 1422.5 |
| cpp-zig-cc-x64-o2 | cpp | 850432 | 830.5 |
| cpp-zig-cc-x86-o0 | cpp | 1427456 | 1394.0 |
| cpp-zig-cc-x86-o2 | cpp | 853504 | 833.5 |
| rust-x64-gnullvm-o0-panic-unwind | rust | 4162560 | 4065.0 |
| rust-x64-gnullvm-o0-panic-abort | rust | 4154880 | 4057.5 |
| rust-x64-gnullvm-o3-panic-unwind | rust | 4162048 | 4064.5 |
| rust-x64-gnullvm-o3-panic-abort | rust | 4154368 | 4057.0 |
| rust-x64-gnullvm-oz-panic-unwind | rust | 4162048 | 4064.5 |
| rust-x64-gnullvm-oz-panic-abort | rust | 4154368 | 4057.0 |
| rust-x64-gnu-o0-panic-unwind | rust | 4908772 | 4793.7 |
| rust-x64-gnu-o0-panic-abort | rust | 4901523 | 4786.6 |
| rust-x64-gnu-o3-panic-unwind | rust | 4908364 | 4793.3 |
| rust-x64-gnu-o3-panic-abort | rust | 4901133 | 4786.3 |
| rust-x64-gnu-oz-panic-unwind | rust | 4908425 | 4793.4 |
| rust-x64-gnu-oz-panic-abort | rust | 4901194 | 4786.3 |
| rust-x64-msvc-o0-panic-unwind | rust | 129024 | 126.0 |
| rust-x64-msvc-o0-panic-abort | rust | 126464 | 123.5 |
| rust-x64-msvc-o3-panic-unwind | rust | 125440 | 122.5 |
| rust-x64-msvc-o3-panic-abort | rust | 123904 | 121.0 |
| rust-x64-msvc-oz-panic-unwind | rust | 125440 | 122.5 |
| rust-x64-msvc-oz-panic-abort | rust | 123904 | 121.0 |
| rust-x86-msvc-o0-panic-unwind | rust | 113664 | 111.0 |
| rust-x86-msvc-o0-panic-abort | rust | 111616 | 109.0 |
| rust-x86-msvc-o3-panic-unwind | rust | 112640 | 110.0 |
| rust-x86-msvc-o3-panic-abort | rust | 111104 | 108.5 |
| rust-x86-msvc-oz-panic-unwind | rust | 112640 | 110.0 |
| rust-x86-msvc-oz-panic-abort | rust | 111104 | 108.5 |
| go-windows-amd64-default | go | 2457088 | 2399.5 |
| go-windows-amd64-noopt | go | 2397184 | 2341.0 |
| go-windows-386-default | go | 2309120 | 2255.0 |
| go-windows-386-noopt | go | 2238464 | 2186.0 |
| zig-x64-debug | zig | 1830400 | 1787.5 |
| zig-x86-debug | zig | 1944064 | 1898.5 |
| zig-x64-releasefast | zig | 754688 | 737.0 |
| zig-x86-releasefast | zig | 755200 | 737.5 |
| zig-x64-releasesmall | zig | 433152 | 423.0 |
| zig-x86-releasesmall | zig | 406528 | 397.0 |
| csharp-framework-win-x64-release | csharp | 162304 | 158.5 |
| csharp-selfcontained-win-x86-release | csharp | 131584 | 128.5 |
| csharp-nativeaot-win-x64-release | csharp | 1105408 | 1079.5 |
| pascal-fpc-win32-o1 | pascal | 34304 | 33.5 |
| pascal-fpc-win32-o3 | pascal | 34304 | 33.5 |
| d-dmd-x64-debug | d | 590336 | 576.5 |
| d-dmd-x64-release | d | 588800 | 575.0 |
| d-dmd-x86-mscoff-release | d | 505856 | 494.0 |
| assembly-nasm-x64-lld | assembly | 1536 | 1.5 |
| assembly-nasm-x86-lld | assembly | 3072 | 3.0 |
| assembly-masm-x64-link | assembly | 2560 | 2.5 |
| assembly-masm-x86-link | assembly | 3072 | 3.0 |
