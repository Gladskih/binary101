"use strict";

// These are possible producer conventions, never unique tool identities.
// Sources and limitations: docs/pe-linker-versions.md.
// https://learn.microsoft.com/en-us/cpp/overview/compiler-versions
const FIXED_LINKER_HINTS = new Map<string, string>([
  // TinyCC's template uses the same bytes as the older Microsoft toolset.
  // https://github.com/TinyCC/tinycc/blob/mob/tccpe.c
  ["6.0", "Microsoft LINK (Visual C++ 6.0 toolset) / TinyCC (fixed 6.0)"],
  // Go's internal PE linker fixes this pair independently of the Go release.
  // https://github.com/golang/go/blob/master/src/cmd/link/internal/ld/pe.go
  ["3.0", "Go internal linker (fixed 3.0)"],
  ["7.0", "Microsoft LINK (Visual Studio .NET 2002 toolset)"],
  ["7.10", "Microsoft LINK 7.10 (Visual Studio .NET 2003 toolset)"],
  ["8.0", "Microsoft LINK (Visual Studio 2005 toolset)"],
  ["9.0", "Microsoft LINK (Visual Studio 2008 toolset)"],
  ["10.0", "Microsoft LINK (Visual Studio 2010 toolset)"],
  // dnlib independently defaults to the same bytes as LINK from VS2012.
  // https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Writer/PEHeaders.cs
  ["11.0", "Microsoft LINK (Visual Studio 2012 toolset) / dnlib PE writer default"],
  ["12.0", "Microsoft LINK (Visual Studio 2013 toolset)"],
  // LLD writes 14/0 for Authenticode compatibility, not its own release number.
  // https://github.com/llvm/llvm-project/blob/main/lld/COFF/Writer.cpp
  ["14.0", "Microsoft LINK (Visual Studio 2015 toolset) / LLVM lld-link (compatibility value)"],
  // Roslyn Compilation fixes minor=0, CSharpCompilation major=0x30 and VB major=&H50.
  // https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/Compilation/Compilation.cs
  // https://github.com/dotnet/roslyn/blob/main/src/Compilers/CSharp/Portable/Compilation/CSharpCompilation.cs
  // https://github.com/dotnet/roslyn/blob/main/src/Compilers/VisualBasic/Portable/Compilation/VisualBasicCompilation.vb
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Reflection.Metadata/src/System/Reflection/PortableExecutable/PEHeaderBuilder.cs
  ["48.0", "Roslyn C# / .NET PEHeaderBuilder default"],
  ["80.0", "Roslyn Visual Basic"],
  // PE_LNK_MINOR is 0x12 (18 decimal), independent of the Watcom product version.
  // https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exepe.h
  ["2.18", "Open Watcom (fixed 2.18)"]
]);

// The internal FPC PE writer packs version/release/patch as major / (release*10+patch).
// Published release names: https://downloads.freepascal.org/fpc/dist/
// https://github.com/fpc/FPCSource/blob/main/compiler/ogcoff.pas
const FREE_PASCAL_HINTS = new Map<string, string>([
  ["2.22", "Free Pascal-style version 2.2.2"],
  ["2.24", "Free Pascal-style version 2.2.4"],
  ["2.40", "Free Pascal-style version 2.4.0"],
  ["2.42", "Free Pascal-style version 2.4.2"],
  ["2.44", "Free Pascal-style version 2.4.4"],
  ["2.60", "Free Pascal-style version 2.6.0"],
  ["2.62", "Free Pascal-style version 2.6.2"],
  ["2.64", "Free Pascal-style version 2.6.4"],
  ["3.0", "Free Pascal-style version 3.0.0"],
  ["3.2", "Free Pascal-style version 3.0.2"],
  ["3.4", "Free Pascal-style version 3.0.4"],
  ["3.20", "Free Pascal-style version 3.2.0"],
  ["3.22", "Free Pascal-style version 3.2.2"],
  // Explicitly checked current development constants; no extrapolation to other snapshots.
  // https://github.com/fpc/FPCSource/blob/main/compiler/version.pas
  ["3.31", "Free Pascal internal linker (3.3.1 development version)"]
]);

// Explicit documented minor components avoid guessing future releases or filling gaps.
// In particular, toolset v141 is not PE linker 14.1, nor is v142 PE linker 14.2.
// https://learn.microsoft.com/en-us/cpp/overview/compiler-versions
const MICROSOFT_14_TOOLSETS = new Map<number, string>([
  ...[10, 11, 12, 13, 14, 15, 16].map(minor =>
    [minor, "Microsoft LINK (Visual Studio 2017 toolsets)"] as const),
  ...[20, 21, 22, 23, 24, 25, 26, 27, 28, 29].map(minor =>
    [minor, "Microsoft LINK (Visual Studio 2019 toolsets)"] as const),
  ...[30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44].map(minor =>
    [minor, "Microsoft LINK (Visual Studio 2022 toolsets)"] as const),
  // MSVC 14.5x release numbering is decoupled from individual VS updates.
  ...[50, 51, 52].map(minor => [minor, "Microsoft LINK (MSVC 14.5x toolsets)"] as const)
]);

// Published release families only; this is an encoding-style match, not a signature.
// https://ftp.gnu.org/gnu/binutils/
// BFD encodes its release major/minor in vstamp unless an input value is preserved:
// https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/master/bfd/peXXigen.c
const GNU_BINUTILS_2_MINORS = new Set([
  7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
  27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47
]);

export const linkerVersionHint = (major: number, minor: number): string => {
  const version = `${major}.${minor}`;
  const candidates = [
    FIXED_LINKER_HINTS.get(version),
    FREE_PASCAL_HINTS.get(version),
    major === 14 ? MICROSOFT_14_TOOLSETS.get(minor) : undefined,
    major === 2 && GNU_BINUTILS_2_MINORS.has(minor) ? "GNU ld/BFD-style version" : undefined
  ].filter(name => name !== undefined).join(" / ");
  return candidates ? `${version} (possible: ${candidates})` : version;
};
