// @ts-nocheck
"use strict";

export const ELF_CLASS = [
  [1, "ELF32", "32-bit objects with 4-byte addresses."],
  [2, "ELF64", "64-bit objects with 8-byte addresses."]
];

export const ELF_DATA = [
  [1, "Little endian", "Least-significant byte first (LSB)."],
  [2, "Big endian", "Most-significant byte first (MSB)."]
];

export const ELF_TYPE = [
  [0, "No type", "Unspecified."],
  [1, "Relocatable", "Object file used for linking."],
  [2, "Executable", "Loadable image with an entry point."],
  [3, "Shared object", "Position-independent library."],
  [4, "Core dump", "Process image captured after a crash."]
];

export const ELF_MACHINE = [
  [0, "No machine"],
  [3, "Intel 80386"],
  [7, "Intel 80860"],
  [8, "MIPS"],
  [20, "PowerPC"],
  [21, "PowerPC64"],
  [40, "ARM"],
  [50, "IA-64"],
  [62, "x86-64"],
  [183, "AArch64"],
  [243, "RISC-V"],
  [247, "BPF"],
  [257, "LoongArch"]
];

export const PROGRAM_TYPES = [
  [0, "PT_NULL", "Unused program header entry."],
  [1, "PT_LOAD", "Loadable segment."],
  [2, "PT_DYNAMIC", "Dynamic linking information."],
  [3, "PT_INTERP", "Program interpreter path."],
  [4, "PT_NOTE", "Auxiliary information notes."],
  [5, "PT_SHLIB", "Reserved (should not appear)."],
  [6, "PT_PHDR", "Program header table itself."],
  [7, "PT_TLS", "Thread-local storage template."],
  [0x6474e550, "GNU_EH_FRAME", "Exception handling frames (GNU)."],
  [0x6474e551, "GNU_STACK", "Stack flags (GNU)."],
  [0x6474e552, "GNU_RELRO", "Relocations read-only after relocations (GNU)."]
];

export const SECTION_TYPES = [
  [0, "SHT_NULL", "Unused."],
  [1, "SHT_PROGBITS", "Program-defined contents."],
  [2, "SHT_SYMTAB", "Linker symbol table."],
  [3, "SHT_STRTAB", "String table."],
  [4, "SHT_RELA", "Relocation entries with addends."],
  [5, "SHT_HASH", "Symbol hash table."],
  [6, "SHT_DYNAMIC", "Dynamic linking information."],
  [7, "SHT_NOTE", "Auxiliary information notes."],
  [8, "SHT_NOBITS", "Zero-initialized data (BSS)."],
  [9, "SHT_REL", "Relocation entries without addends."],
  [10, "SHT_SHLIB", "Reserved (should not appear)."],
  [11, "SHT_DYNSYM", "Dynamic symbol table."],
  [0x6ffffff6, "GNU_HASH", "GNU-style hash table."],
  [0x6ffffff7, "GNU_LIBLIST", "Prelink library list."],
  [0x6ffffffd, "GNU_VERDEF", "Version definitions."],
  [0x6ffffffe, "GNU_VERNEED", "Version requirements."],
  [0x6fffffff, "GNU_VERSYM", "Version symbol table."]
];

export const SECTION_FLAGS = [
  [0x1, "WRITE", "Section is writable at runtime."],
  [0x2, "ALLOC", "Occupies memory when loaded."],
  [0x4, "EXECINSTR", "Contains executable code."],
  [0x10, "MERGE", "May be merged to eliminate duplicates."],
  [0x20, "STRINGS", "Contains NUL-terminated strings."],
  [0x40, "INFO_LINK", "sh_info field has extra meaning."],
  [0x80, "LINK_ORDER", "Special ordering requirements."],
  [0x100, "OS_NONCONFORMING", "Requires OS-specific processing."],
  [0x200, "GROUP", "Section is part of a group."],
  [0x400, "TLS", "Thread-local storage."],
  [0x0ff00000, "MASKOS", "OS-specific flags."],
  [0xf0000000, "MASKPROC", "Processor-specific flags."]
];

export const PROGRAM_FLAGS = [
  [0x1, "X", "Execute permission."],
  [0x2, "W", "Writable."],
  [0x4, "R", "Readable."]
];
