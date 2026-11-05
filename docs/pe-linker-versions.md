# PE linker version hints

Reviewed on 2026-11-06. `MajorLinkerVersion` and `MinorLinkerVersion` are separate
unsigned bytes, as specified in the [PE optional header](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
The renderer preserves the integer pair and lists **possible** producers only for
catalogued conventions. It does not identify the compiler, linker executable,
installed IDE, programming language, or build environment from this field alone.

The value is producer-written metadata. PE writers can select arbitrary bytes,
reuse another tool's version, or preserve an existing image's value. A name in the
catalogue is therefore a candidate, not an exclusive signature. Unknown pairs stay
numeric without warnings or an automatic MSVC attribution.

## Microsoft toolset generations

[Microsoft's compiler and Build Tools version table](https://learn.microsoft.com/en-us/cpp/overview/compiler-versions)
provides the generation labels. The renderer recognizes these explicit minor sets:

| Pair or minor set | Possible generation |
| --- | --- |
| 6.0 | Visual C++ 6.0 |
| 7.0 | Visual Studio .NET 2002 |
| 7.10 | Microsoft LINK 7.10 / Visual Studio .NET 2003 |
| 8.0, 9.0, 10.0, 11.0, 12.0 | Visual Studio 2005, 2008, 2010, 2012, 2013 respectively |
| 14.0 | Visual Studio 2015; also LLD's compatibility convention |
| 14.10–14.16 | Visual Studio 2017 toolsets |
| 14.20–14.29 | Visual Studio 2019 toolsets |
| 14.30–14.44 | Visual Studio 2022 toolsets |
| 14.50, 14.51, 14.52 | MSVC 14.5x toolsets; no particular IDE update inferred |

These are toolset-generation hints, not evidence of which IDE was used. Older
toolsets can be installed in newer IDEs; MSVC 14.5x versioning is explicitly
decoupled from individual Visual Studio updates. Microsoft's table includes
14.52 as a preview, so a candidate label is not a claim about stable-release status.

Do not confuse the toolset names v141/v142/v143 with the integer pairs 14/1,
14/2 or 14/3. Those three pairs remain unattributed. Likewise, no unknown minor
falls back to the label for the same major with minor zero. The legacy LINK
representation 7/10 is also visible in the PE example in the authors'
[bulk_extractor manual](https://digitalcorpora.s3.amazonaws.com/downloads/bulk_extractor/BEUsersManual.pdf);
it must not be shortened to 7/1 because a product table calls the toolset 7.1.

## Other producers and known collisions

| Header pair | Confirmed convention |
| --- | --- |
| 14.0 | LLD deliberately writes this for Authenticode compatibility, independently of the LLD release. |
| 48.0 | Roslyn C# uses major 0x30; .NET PEHeaderBuilder independently defaults to the same pair. |
| 80.0 | Roslyn Visual Basic uses major 0x50. |
| 11.0 | dnlib defaults to this pair, colliding with a Microsoft LINK generation. |
| 2.18 | Open Watcom's fixed major 2 / minor 0x12, also consistent with GNU BFD's release-style encoding. |
| 2.7–2.47 | Possible GNU ld/BFD-style encoding for published release families. |
| 6.0 | TinyCC's fixed template value, colliding with an older Microsoft LINK generation. |
| 3.0 | Go's fixed internal-linker value, also matching Free Pascal's encoding for 3.0.0. |
| 2.22, 2.24, 2.40, 2.42, 2.44, 2.60, 2.62, 2.64; 3.0, 3.2, 3.4, 3.20, 3.22 | Free Pascal-style major / (release*10 + patch), restricted to published release names. Several 2.x pairs overlap GNU's convention. |
| 3.31 | Current Free Pascal development constants 3.3.1; explicitly labelled as development. |

GNU's [published archive](https://ftp.gnu.org/gnu/binutils/) establishes the release
families. The BFD writer provides the encoding rule. The renderer matches the
combination, without claiming that every historical release was independently
built and inspected. It does not extrapolate to hypothetical later releases.
In particular, the pair 2.18 is neither a unique Watcom signature nor proof of
an installed product called Open Watcom 2.18.

Free Pascal's [published archive](https://downloads.freepascal.org/fpc/dist/)
establishes the release names used with its internal PE writer's encoding rule.
These are also style matches, without a claim that every historical release was
independently rebuilt. External linking can instead produce the external linker's
header values. Go's fixed value is likewise specific to its internal PE writer;
it must not be interpreted as a Go compiler release called 3.0.

## Source snapshots

- [LLD Writer.cpp](https://github.com/llvm/llvm-project/blob/6273f264aa88c8fc55d3fec231f80638bca1de13/lld/COFF/Writer.cpp): writes linker major 14, minor 0 and explains the compatibility reason.
- [Roslyn CSharpCompilation](https://github.com/dotnet/roslyn/blob/3fdf3c3fff5747937bf99568f41bf12db657e014/src/Compilers/CSharp/Portable/Compilation/CSharpCompilation.cs): `LinkerMajorVersion` is 0x30.
- [Roslyn VisualBasicCompilation](https://github.com/dotnet/roslyn/blob/3fdf3c3fff5747937bf99568f41bf12db657e014/src/Compilers/VisualBasic/Portable/Compilation/VisualBasicCompilation.vb): corresponding major is 0x50.
- [Roslyn Compilation](https://github.com/dotnet/roslyn/blob/3fdf3c3fff5747937bf99568f41bf12db657e014/src/Compilers/Core/Portable/Compilation/Compilation.cs): supplies minor zero and explains the language-specific major convention.
- [.NET PEHeaderBuilder](https://github.com/dotnet/runtime/blob/9789d45f9adabc3bcfaf5aecd52c794f8eb9cae5/src/libraries/System.Reflection.Metadata/src/System/Reflection/PortableExecutable/PEHeaderBuilder.cs): constructor defaults to major 0x30 / minor zero.
- [dnlib PEHeaders](https://github.com/0xd4d/dnlib/blob/9871d3b290589a9316dc68439d1c5307411d5dc5/src/DotNet/Writer/PEHeaders.cs): defaults to major 11 / minor zero and writes both bytes.
- [Open Watcom exepe.h](https://github.com/open-watcom/open-watcom-v2/blob/558748e2bd28d330e37c0a2f2d8a2a4766118625/bld/watcom/h/exepe.h) and [loadpe.c](https://github.com/open-watcom/open-watcom-v2/blob/558748e2bd28d330e37c0a2f2d8a2a4766118625/bld/wl/c/loadpe.c): define and emit major 2 / minor 0x12.
- [GNU BFD peXXigen.c](https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/2364e17098e63e0af17c5329dec1ca8cd82c6cbb/bfd/peXXigen.c): encodes the BFD release major/minor when no supplied linker version is preserved.
- [TinyCC tccpe.c](https://github.com/TinyCC/tinycc/blob/2d3eea205cb6c0f796d01d7d0858eb6c6c1d993f/tccpe.c): its optional-header template uses 6/0.
- [Go pe.go](https://github.com/golang/go/blob/521dd20174c75a3e8a20fb5a274822c5c2284b94/src/cmd/link/internal/ld/pe.go): writes 3/0 for PE32 and PE32+.
- [Free Pascal ogcoff.pas](https://github.com/fpc/FPCSource/blob/74414fe5bfb5bf6b536a64c0a79efa43ebdf1c49/compiler/ogcoff.pas) and [version.pas](https://github.com/fpc/FPCSource/blob/74414fe5bfb5bf6b536a64c0a79efa43ebdf1c49/compiler/version.pas): encode version characters as major and release*10+patch; the reviewed development constants are 3.3.1.

This is a bounded catalogue, not an exhaustive inventory of PE-producing tools.
Additional Borland/Embarcadero, Delphi, Intel, managed, custom and historical
conventions require their own exact-byte evidence. A broad numeric
resemblance or a neighbouring known version is insufficient to add an attribution.
Rich-header records and other metadata can be separate corroborating evidence;
this formatter does not turn them into a unique identification claim.
