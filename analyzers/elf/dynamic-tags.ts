import { ELF_DYNAMIC_TAG } from "./abi-constants.js";

type DynamicValueKind = "address" | "bytes" | "count" | "string" | "presence" |
  "flags" | "relocation" | "value";
type DynamicTagCatalog = Readonly<Record<number, readonly [string, DynamicValueKind, string]>>;

// Numeric assignments and semantics: gABI 8.3 and glibc elf/elf.h (GNU/Sun extensions).
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
// https://github.com/bminor/glibc/blob/master/elf/elf.h
// Sun string tags: https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/
export const ELF_DYNAMIC_TAG_DESCRIPTIONS: DynamicTagCatalog = {
  1: ["DT_NEEDED", "string", "Required shared library; order is significant."],
  2: ["DT_PLTRELSZ", "bytes", "Total size of PLT relocations."],
  3: ["DT_PLTGOT", "address", "PLT/GOT address; details depend on the processor ABI."],
  4: ["DT_HASH", "address", "System V symbol hash table."],
  5: ["DT_STRTAB", "address", "Dynamic string table."],
  6: ["DT_SYMTAB", "address", "Dynamic symbol table."],
  7: ["DT_RELA", "address", "Relocations with explicit addends."],
  8: ["DT_RELASZ", "bytes", "Total size of RELA relocations."],
  9: ["DT_RELAENT", "bytes", "Size of one RELA record."],
  10: ["DT_STRSZ", "bytes", "Dynamic string table size."],
  11: ["DT_SYMENT", "bytes", "Size of one dynamic symbol."],
  12: ["DT_INIT", "address", "Initialization function."],
  13: ["DT_FINI", "address", "Termination function."],
  14: ["DT_SONAME", "string", "Shared object's own library name."],
  15: ["DT_RPATH", "string", "Legacy library search path. On glibc it may apply down the dependency tree and is ignored if this object has DT_RUNPATH. $ORIGIN refers to the containing object's directory."],
  16: ["DT_SYMBOLIC", "presence", "Search this object first; superseded by DF_SYMBOLIC."],
  17: ["DT_REL", "address", "Relocations with implicit addends."],
  18: ["DT_RELSZ", "bytes", "Total size of REL relocations."],
  19: ["DT_RELENT", "bytes", "Size of one REL record."],
  20: ["DT_PLTREL", "relocation", "Encoding used by all PLT relocations."],
  21: ["DT_DEBUG", "value", "Debugger information; contents are unspecified by the gABI."],
  22: ["DT_TEXTREL", "presence", "Relocations may modify non-writable segments; superseded by DF_TEXTREL."],
  23: ["DT_JMPREL", "address", "Relocation table for the PLT."],
  24: ["DT_BIND_NOW", "presence", "Resolve relocations before execution; superseded by DF_BIND_NOW."],
  25: ["DT_INIT_ARRAY", "address", "Array of initialization function pointers."],
  26: ["DT_FINI_ARRAY", "address", "Array of termination function pointers."],
  27: ["DT_INIT_ARRAYSZ", "bytes", "Initialization array size."],
  28: ["DT_FINI_ARRAYSZ", "bytes", "Termination array size."],
  29: ["DT_RUNPATH", "string", "Search path for this object's direct DT_NEEDED dependencies. $ORIGIN refers to the containing object's directory."],
  30: ["DT_FLAGS", "flags", "Dynamic loader behavior flags (DF_*)."],
  32: ["DT_PREINIT_ARRAY", "address", "Pre-initialization function pointers; executable files only."],
  33: ["DT_PREINIT_ARRAYSZ", "bytes", "Pre-initialization array size."],
  34: ["DT_SYMTAB_SHNDX", "address", "Extended section indices for dynamic symbols."],
  35: ["DT_RELRSZ", "bytes", "Total size of RELR relocations."],
  36: ["DT_RELR", "address", "Packed relative relocation table."],
  37: ["DT_RELRENT", "bytes", "Size of one RELR record."],
  39: ["DT_SYMTABSZ", "bytes", "Dynamic symbol table size (gABI)."],
  // Experimental assignment: llvm/include/llvm/BinaryFormat/DynamicTags.def
  // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/DynamicTags.def
  [ELF_DYNAMIC_TAG.CREL]: ["DT_CREL", "address",
    "Packed relocation table using the experimental LLVM CREL encoding."],
  0x6ffffdf5: ["DT_GNU_PRELINKED", "value", "GNU prelink timestamp."],
  0x6ffffdf6: ["DT_GNU_CONFLICTSZ", "bytes", "GNU conflict table size."],
  0x6ffffdf7: ["DT_GNU_LIBLISTSZ", "bytes", "GNU library list size."],
  0x6ffffdf8: ["DT_CHECKSUM", "value", "Object checksum."],
  0x6ffffdf9: ["DT_PLTPADSZ", "bytes", "PLT padding size."],
  0x6ffffdfa: ["DT_MOVEENT", "bytes", "Size of one move record."],
  0x6ffffdfb: ["DT_MOVESZ", "bytes", "Move table size."],
  0x6ffffdfc: ["DT_FEATURE_1", "flags", "Feature selection flags (DTF_1_*)."],
  0x6ffffdfd: ["DT_POSFLAG_1", "flags", "Flags applying only to the following dynamic entry."],
  0x6ffffdfe: ["DT_SYMINSZ", "bytes", "Symbol information table size."],
  0x6ffffdff: ["DT_SYMINENT", "bytes", "Size of one symbol information record."],
  0x6ffffef5: ["DT_GNU_HASH", "address", "GNU symbol hash table."],
  0x6ffffef6: ["DT_TLSDESC_PLT", "address", "TLS descriptor PLT entry."],
  0x6ffffef7: ["DT_TLSDESC_GOT", "address", "TLS descriptor GOT entry."],
  0x6ffffef8: ["DT_GNU_CONFLICT", "address", "GNU conflict table."],
  0x6ffffef9: ["DT_GNU_LIBLIST", "address", "GNU library list."],
  0x6ffffefa: ["DT_CONFIG", "string", "Runtime linker configuration file name."],
  0x6ffffefb: ["DT_DEPAUDIT", "string", "Audit libraries for dependencies."],
  0x6ffffefc: ["DT_AUDIT", "string", "Audit libraries for this object."],
  0x6ffffefd: ["DT_PLTPAD", "address", "PLT padding."],
  0x6ffffefe: ["DT_MOVETAB", "address", "Move table."],
  0x6ffffeff: ["DT_SYMINFO", "address", "Symbol information table."],
  0x6ffffff0: ["DT_VERSYM", "address", "Symbol version indices."],
  0x6ffffff9: ["DT_RELACOUNT", "count", "Leading relative relocations in DT_RELA."],
  0x6ffffffa: ["DT_RELCOUNT", "count", "Leading relative relocations in DT_REL."],
  0x6ffffffb: ["DT_FLAGS_1", "flags", "Extended loader behavior flags (DF_1_*)."],
  0x6ffffffc: ["DT_VERDEF", "address", "Version definition table."],
  0x6ffffffd: ["DT_VERDEFNUM", "count", "Number of version definitions."],
  0x6ffffffe: ["DT_VERNEED", "address", "Required symbol version table."],
  0x6fffffff: ["DT_VERNEEDNUM", "count", "Number of required version records."],
  0x7ffffffd: ["DT_AUXILIARY", "string",
    "Alternative library whose symbol implementations are preferred over this object's own."],
  0x7fffffff: ["DT_FILTER", "string",
    "Library supplying actual code and data for the symbols declared by this object."]
};

// Processor-specific tag numbers are meaningful only for the corresponding e_machine.
// https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#dynamic-section
// https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_dynamic_section
const aarch64Tags: DynamicTagCatalog = { ...ELF_DYNAMIC_TAG_DESCRIPTIONS,
  0x70000005: ["DT_AARCH64_VARIANT_PCS", "value",
    "Marks a PLT relocation against a variant-PCS symbol. The loader must preserve its calling convention. The value is unused."]
};
const riscvTags: DynamicTagCatalog = { ...ELF_DYNAMIC_TAG_DESCRIPTIONS,
  0x70000001: ["DT_RISCV_VARIANT_CC", "value",
    "Marks a PLT relocation against a symbol with a variant calling convention."]
};

export const elfDynamicTagCatalog = (machine?: number): DynamicTagCatalog =>
  machine === 183 ? aarch64Tags : machine === 243 ? riscvTags : ELF_DYNAMIC_TAG_DESCRIPTIONS;
