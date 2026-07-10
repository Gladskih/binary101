# Microsoft C++ RTTI analysis

Binary101 recognizes a deliberately narrow Microsoft C++ ABI RTTI layout in native PE images.
The reported layout identifier is
`microsoft-cxx-amd64-image-relative-rtti-rev1`.

## Supported layout

The first revision supports only PE32+ AMD64 images using the modern Win64 image-relative
Microsoft C++ RTTI records. A complete object locator must have revision-1 signature `1` and a
`pSelf` image-relative reference to itself. Support is determined from the PE machine, optional
header, relocation evidence, and RTTI graph; it is not inferred from a compiler name. Compatible
output from MSVC or `clang-cl` can therefore be recognized.

The record definitions and flags were checked against the Microsoft C++ ABI implementation in
[LLVM `MicrosoftCXXABI.cpp`](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/MicrosoftCXXABI.cpp)
and the `rttidata.h` and `ehdata_forceinclude.h` headers from MSVC 14.51.36231. The analyzer reads:

- `RTTICompleteObjectLocator` revision 1, including `pSelf`;
- the two pointer-sized `TypeDescriptor` fields and its bounded NUL-terminated decorated name;
- `RTTIClassHierarchyDescriptor` and its image-relative `RTTIBaseClassArray`;
- the 28-byte image-relative `RTTIBaseClassDescriptor`, including its
  `pClassDescriptor` field and `BCD_HASPCHD` attribute;
- `PMD`, whose `mdisp`, `pdisp`, and `vdisp` members are signed 32-bit values.

Only the documented class-hierarchy flags (`CHD_MULTINH`, `CHD_VIRTINH`, and `CHD_AMBIGUOUS`)
and base-class flags through `BCD_HASPCHD` are accepted. Unknown bits invalidate a candidate.
Decorated class and struct names are retained as emitted; Binary101 does not partially demangle
them.

## Strict relocation-backed detection

The analyzer consumes the Base Relocation Directory already parsed by the PE pipeline. It does
not parse `.reloc` again and does not scan `.rdata` for an RTTI signature.

1. It indexes valid `IMAGE_REL_BASED_DIR64` sites as `block.pageRva + entry.offset`.
2. At each aligned site in a file-backed, readable, initialized, non-executable section it reads
   the stored preferred 64-bit VA, converts it through `ImageBase`, and treats the resulting RVA
   only as a COL candidate.
3. It accepts the candidate only after the complete COL, `pSelf`, `TypeDescriptor`, class
   hierarchy, base descriptor array, extra hierarchy references, and inheritance tree validate.
4. It then treats the relocation site as `vftable[-1]`. The next 8-byte slot starts a vftable only
   when that slot has its own `DIR64` relocation and its stored preferred VA targets a mapped
   executable range.
5. It extends the vftable only across contiguous 8-byte slots that each have `DIR64` evidence and
   an executable in-image target. The first unconfirmed slot ends the table and is not included.

The PE/COFF definition of base relocation blocks and type 10, `IMAGE_REL_BASED_DIR64`, comes from
the official [Microsoft PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only).
All participating RTTI records and pointer slots must be fully available in file-backed mapped
sections. Arithmetic, alignment, image bounds, and known attribute bits are checked throughout.
Rejected candidates are expected during the relocation walk and do not produce warnings or UI.

## Result and disassembly integration

The `Microsoft C++ RTTI` section reports the layout, unique types, complete object locators,
class hierarchies, inheritance subobjects, confirmed vftables, and their ordered virtual-function
targets. COL `offset` and `cdOffset`, PMD values, hierarchy/base attributes, and original decorated
names remain available. Multiple COLs or vftables for one complete type and repeated base
subobjects are preserved rather than merged by type name.

Every confirmed executable target is also deduplicated by RVA into the `MSVC RTTI vftables`
entrypoint-seed source. A target is an entrypoint candidate only; RTTI does not establish the end
of a function or a function range.

## Deliberate limitations

The analyzer returns `null` unless at least one complete relocation-backed chain reaches a
non-empty vftable. It does not currently support:

- PE32/x86, ARM, or ARM64;
- the older absolute-pointer Microsoft RTTI layout or COL revision 0;
- images without a valid Base Relocation Directory, stripped relocations, or RTTI recovery from
  other evidence;
- MinGW/GCC Itanium C++ ABI RTTI;
- C++ exception metadata, import-based discovery, constructor analysis, or heuristic absolute
  pointer searches;
- full Microsoft-name demangling.

Consequently, the absence of an RTTI result does not prove that an image contains no C++, virtual
classes, or RTTI. It can instead mean that the image uses an unsupported ABI/layout, lacks the
required relocation evidence, was transformed or stripped, or does not contain a fully
file-backed chain.
