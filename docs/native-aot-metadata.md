# NativeAOT metadata detection

Binary101 confirms a deliberately narrow NativeAOT metadata layout in native Windows PE images.
It does not classify a file as NativeAOT from section names or compiler strings alone.

## Strict relocation-backed detection

The first revision supports PE32 x86 and PE32+ AMD64 images with a valid Base Relocation Directory.
It uses `IMAGE_REL_BASED_HIGHLOW` sites for x86 and `IMAGE_REL_BASED_DIR64` sites for AMD64.

1. Each relocated, pointer-aligned slot in file-backed, readable, initialized, non-executable data
   is treated only as a possible module-header pointer.
2. Its preferred VA must resolve inside the image to a pointer-aligned NativeAOT
   `ReadyToRunHeader` with signature `0x00525452`, zero flags, entry type 1, a bounded section
   count, and one of the two supported entry sizes.
3. The section table must be fully file-backed, strictly sorted by type, limited to documented
   shared and NativeAOT section ID ranges, and every section pointer must have matching base
   relocation evidence. Pointer ranges or explicit sizes must remain within one mapped PE section.
4. The graph must contain both a NativeAOT runtime section and section 313, the
   `EmbeddedMetadata` reflection blob.
5. The embedded blob must be fully file-backed and begin with the NativeFormat metadata signature
   `0xDEADDFFD`.

The layouts and constants were checked against the .NET runtime sources:

- [`ModuleHeaders.h`](https://github.com/dotnet/runtime/blob/main/src/coreclr/nativeaot/Runtime/inc/ModuleHeaders.h)
  defines the NativeAOT header;
- [`ReadyToRunHeaderNode.cs`](https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReadyToRunHeaderNode.cs)
  defines emitted entries and pointer relocations;
- [`MetadataBlob.cs`](https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs)
  assigns `EmbeddedMetadata` blob ID 13 within the section range beginning at 300;
- [`NativeMetadataReader.cs`](https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeMetadataReader.cs)
  validates `0xDEADDFFD` as the NativeFormat metadata header signature;
- [`NativeFormatReaderCommonGen.cs`](https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs)
  defines NativeFormat handle kinds;
- [`NativeFormatReaderGen.cs`](https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs)
  defines the generated scope, namespace, type, and method record layouts;
- [`NativeFormatReader.cs`](https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs)
  defines compressed integers, typed handles, and polymorphic handles.

Rejected relocation candidates are expected and remain invisible. A malformed or truncated
relocation/header graph does not throw and is not reported as confirmed NativeAOT metadata. If only
weaker evidence exists, the existing `Native AOT candidate` result remains explicitly labelled as
conservative.

## Result and limitations

The `NativeAOT metadata` section reports the header layout and version, the relocation-backed
module pointer, and the ordered ReadyToRun section table, including the embedded reflection
metadata RVA and size. It also walks the embedded NativeFormat graph and reports:

- reflection scopes with assembly name, module name, and assembly version;
- namespace-qualified type definitions, including nested type names;
- method names retained for reflection.

NativeFormat is an internal format without a separate compatible format-version field. The deep
decoder therefore validates every compressed value, handle kind, offset, collection count, UTF-8
string, and traversal limit that it consumes. It deliberately stops reading each record after the
last field needed for the reported result, so an unsupported unused tail cannot hide useful names.
A malformed or unsupported consumed field produces visible warnings but does not retract the
independently confirmed NativeAOT result.

Only metadata retained by NativeAOT for reflection can be shown. Trimmed types or methods are not
recoverable from this blob. Signatures, fields, properties, events, custom attributes, and mappings
from reflection method names to code addresses are not decoded yet.

## Initializer entry points for disassembly

Confirmed PE (x86/AMD64) and ELF (x86-64) NativeAOT images now provide disassembly seeds from:

- section 205, `EagerCctor`: eager class constructors;
- section 213, `ModuleInitializerList`: module constructors.

Both contain signed little-endian 32-bit displacements relative to the address of each slot,
including on 64-bit targets. The parser follows the runtime's `RunInitializers` implementation;
it does not scan for pointer-shaped values or infer function prologues.

Decoding is deliberately restricted to the exact verified header versions **10.1 (.NET 9)** and
**16.0 (.NET 10)**. Sources checked at the release tags:

- [v9.0.0 ModuleHeaders.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs)
  and [v10.0.0 ModuleHeaders.cs](https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs): versions and section IDs;
- [v9.0.0 StartupCodeHelpers.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/CompilerHelpers/StartupCodeHelpers.cs)
  and [v10.0.0 StartupCodeHelpers.cs](https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/CompilerHelpers/StartupCodeHelpers.cs): runtime interpretation of both tables;
- [v9.0.0 TargetDetails.cs](https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/TypeSystem/Common/TargetDetails.cs)
  and [v10.0.0 TargetDetails.cs](https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/TypeSystem/Common/TargetDetails.cs): relative pointers on supported targets;
- [ModuleInitializerListNode.cs](https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ModuleInitializerListNode.cs): compiler emission of method entry-point references.

.NET 8 header version 9.1 is intentionally excluded: its
[TargetDetails.cs](https://github.com/dotnet/runtime/blob/v8.0.0/src/coreclr/tools/Common/TypeSystem/Common/TargetDetails.cs)
also permits CppCodegen with absolute pointers, which the header does not distinguish. Unknown
versions produce a visible warning for each initializer table, without guessing its encoding.

Each table needs an explicit, aligned, fully file-backed extent divisible by four. Each target must
resolve to executable bytes within both the file and mapped image. A bad extent, unreadable chunk,
or invalid target rejects the entire table's seeds, while other valid tables remain available.
Warnings remain visible without retracting independently confirmed NativeAOT metadata. The parser
limits each table to 1 MiB and reads at most 4 KiB at a time through the existing range reader.

Targets are deduplicated per table. PE and ELF disassembly reuse the parsed addresses, retain their
source labels, and apply the existing cross-source deduplication. The NativeAOT panel shows counts
and warnings. This does not recover method names or all compiled methods: reflection invoke maps,
stack-trace maps, general fixup tables, and hydrated runtime structures are not seed sources here.

The analyzer currently does not confirm ARM/ARM64, files with stripped or malformed base
relocations, metadata that is not fully file-backed, or NativeAOT images whose header layout uses an
unknown entry encoding. Absence of a confirmed result does not prove that a file is not NativeAOT.
