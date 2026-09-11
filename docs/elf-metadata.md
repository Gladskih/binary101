# ELF metadata analysis

The browser parses ELF locally. The metadata views include:

- GNU symbol definitions and requirements, including version names, parent names,
  library names, flags and symbol version indices. Imports and exports show `@`
  and `@@` suffixes. Version tables can come from sections or dynamic tags.
- Complete `SHT_SYMTAB` entries, including local and section symbols and extended
  section indices. Tables support pagination and sorting. Relocation analysis
  reuses decoded names.
- GNU property descriptors: stack size, no-copy declarations, x86 ISA requirements
  and usage, IBT/SHSTK compatibility, and AArch64 BTI/PAC/GCS declarations. These
  declarations do not prove that a running process enables a protection.
- Section groups, COMDAT flags, signatures and member sections. Invalid signature
  references, duplicate memberships and missing `SHF_GROUP` flags produce notices.
- `.eh_frame` and `.debug_frame` CIE/FDE records, PC ranges, personality and LSDA
  pointers, and decoded CFI instructions with their encoded operands.

System V `.hash` and GNU `.gnu.hash` tables expose buckets, chains and Bloom words,
including tables found through dynamic tags without section headers. Validation
reports truncated arrays, invalid indices, cycles and malformed GNU chains. GNU
hashes and Bloom membership are checked against decoded dynamic symbol names.
The external hash test compares the bucket histogram with WSL libc's `readelf -I` output.

ARM `.ARM.attributes` and RISC-V `.riscv.attributes` decode vendor records,
file/section/symbol scopes, index lists and integer/string attributes. ARM
compatibility tuples retain both values. Unsupported vendors/scopes and unknown
mandatory RISC-V tags produce notices. Cross-compiled WSL Clang objects are
compared with `readelf -A` for both architectures.

MIPS `.MIPS.abiflags`, `.reginfo` and `.MIPS.options` expose ABI flags, register
masks and GP values. Register layouts are separate for ELF32 and ELF64. ABI flags
and register info can also be located through their program headers. Options
decode REGINFO payloads and report other payload kinds explicitly. WSL Clang
MIPS32/MIPS64 objects are compared with `readelf -A`.

Linux `ET_CORE` files decode `NT_PRSTATUS`, `NT_PRPSINFO`, `NT_AUXV`, `NT_FILE`
and the signal/errno/code fields of `NT_SIGINFO`. General registers and process
layouts cover i386, x86-64 and AArch64. Floating point registers cover x86-64
FXSAVE and AArch64 FPSIMD. XSAVE feature masks are decoded, while extended
component payloads and unsupported core ABIs produce explicit notices. Metadata,
registers and mappings have paged tables. Note reads are bounded to 16 MiB.

## Unwind boundaries

The unwind view evaluates CFI into virtual CFA/register rules for PC ranges,
including CIE defaults, alignment factors, saved states and register restores.
It does not unwind a live register/memory state. DWARF expression operands remain hex bytes. Indirect pointers
identify pointer storage and are not dereferenced through a runtime loader.

Supported CIE revisions are 1, 3 and 4, with 4- or 8-byte unsegmented addresses and
the `z`, `P`, `L`, `R`, `S` augmentations. Pointer formats include fixed-width signed
and unsigned values, ULEB128 and SLEB128, with absolute or PC-relative addressing.
Unknown encodings, revisions or instructions produce notices.

Compressed unwind sections and sections requiring relocations are reported but
not decoded. Full unwind parsing currently requires section headers; the existing
instruction-set analysis can still use `PT_GNU_EH_FRAME` as a source of entry points.
GCC/LLVM LSDA payloads in `.gcc_except_table` decode call sites, action chains,
reverse type pointers and exception-specification index lists. Reads are bounded
by the next LSDA or the section end. Other language-specific payload formats and
indirect LSDA addresses produce notices. Indirect type pointers remain storage
addresses; exception matching is not executed. ARM EHABI tables and SFrame remain unsupported.

Reads use bounded ranges. Resource limits also bound retained entries and individual
names, expressions and CFI instruction sequences; reaching a limit produces a notice.

## Verification

Run `npm run test:coverage`, `npm run lint`, `npm run typecheck`, `npm run build`
and `npm run test:e2e`. External ELF comparisons are separate:

```powershell
npx tsx --test tests/external/analyzers.elf.*readelf.test.ts
```

The external tests compare with GNU `readelf` in WSL. They cover the system ELF
corpus, real GCC object files, a libstdc++ archive member, and `ls`, `bash` and libc.
Versions and GNU properties are also checked after removing section headers from
copies. The browser test loads WSL libc and opens metadata and CFI views.

These external tests skip when WSL/readelf is unavailable; some require the GCC
runtime/development files and x86-64 libc present in the tested WSL installation.

Format references: [ELF gABI](https://gabi.xinuos.com/elf/),
[LSB symbol versions](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html),
[LSB exception frames](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html),
[glibc ELF declarations](https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h),
and [LLVM DWARF declarations](https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/BinaryFormat/Dwarf.def).
