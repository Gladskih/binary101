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
recoverable from this blob. Signatures, fields, properties, events, custom attributes, and method
code addresses are not decoded yet.

The analyzer currently does not confirm ARM/ARM64, files with stripped or malformed base
relocations, metadata that is not fully file-backed, or NativeAOT images whose header layout uses an
unknown entry encoding. Absence of a confirmed result does not prove that a file is not NativeAOT.
