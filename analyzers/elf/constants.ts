"use strict";

import type { ElfOptionEntry } from "./types.js";

export const ELF_CLASS: ElfOptionEntry[] = [
  [1, "ELF32", "32-bit objects with 4-byte addresses."],
  [2, "ELF64", "64-bit objects with 8-byte addresses."]
];

export const ELF_DATA: ElfOptionEntry[] = [
  [1, "Little endian", "Least-significant byte first (LSB)."],
  [2, "Big endian", "Most-significant byte first (MSB)."]
];

export const ELF_TYPE: ElfOptionEntry[] = [
  [0, "No type", "Unspecified."],
  [1, "Relocatable", "Object file used for linking."],
  [2, "Executable", "Loadable image with an entry point."],
  [3, "Shared object", "Position-independent library."],
  [4, "Core dump", "Process image captured after a crash."]
];

export const ELF_MACHINE: ElfOptionEntry[] = [
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

export const PROGRAM_TYPES: ElfOptionEntry[] = [
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

export const SECTION_TYPES: ElfOptionEntry[] = [
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

export const SECTION_FLAGS: ElfOptionEntry[] = [
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

export const PROGRAM_FLAGS: ElfOptionEntry[] = [
  [0x1, "X", "Execute permission."],
  [0x2, "W", "Writable."],
  [0x4, "R", "Readable."]
];

/*
 * Dynamic flag bit assignments are synchronized with glibc <elf.h>:
 * https://sources.debian.org/src/glibc/2.31-13%2Bdeb11u3/elf/elf.h/#L4880
 *
 * Human-readable behavior notes are based on:
 * - Oracle Solaris Linker and Libraries Guide, "Dynamic Section", Tables 13-9 and 13-10:
 *   https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
 *
 * Some bits (for example DF_1_TRANS, DF_1_STUB, DF_1_KMOD, DF_1_WEAKFILTER,
 * DF_1_NOCOMMON) have limited cross-platform documentation; their semantics
 * can be ABI/toolchain specific.
 */
export const DYNAMIC_FLAGS: ElfOptionEntry[] = [
  [0x1, "DF_ORIGIN", "The loader may resolve $ORIGIN in paths."],
  [0x2, "DF_SYMBOLIC", "Prefer this object for symbol resolution before dependencies."],
  [0x4, "DF_TEXTREL", "Text relocations are present (code pages may need temporary writes)."],
  [0x8, "DF_BIND_NOW", "Resolve relocations eagerly at load time."],
  [0x10, "DF_STATIC_TLS", "Object uses static TLS model requirements."]
];

export const DYNAMIC_FLAGS_1: ElfOptionEntry[] = [
  [0x00000001, "DF_1_NOW", "Resolve relocations eagerly (similar to BIND_NOW)."],
  [0x00000002, "DF_1_GLOBAL", "Make symbols available for global symbol searches."],
  [0x00000004, "DF_1_GROUP", "Restrict lookups to this object group."],
  [0x00000008, "DF_1_NODELETE", "Do not unload this object after dlclose."],
  [0x00000010, "DF_1_LOADFLTR", "Load filtees immediately, not lazily."],
  [0x00000020, "DF_1_INITFIRST", "Run this object's init before others in the process."],
  [0x00000040, "DF_1_NOOPEN", "Disallow using this object with dlopen."],
  [0x00000080, "DF_1_ORIGIN", "Object may use $ORIGIN substitution."],
  [0x00000100, "DF_1_DIRECT", "Enable direct binding when supported."],
  [0x00000200, "DF_1_TRANS", "ABI/toolchain-specific semantics."],
  [0x00000400, "DF_1_INTERPOSE", "Interpose this object's symbols ahead of others."],
  [0x00000800, "DF_1_NODEFLIB", "Ignore default library search paths."],
  [0x00001000, "DF_1_NODUMP", "Prevent this object from being dumped."],
  [0x00002000, "DF_1_CONFALT", "Use an alternative configuration path (platform-specific)."],
  [0x00004000, "DF_1_ENDFILTEE", "Stop processing filtee dependencies after this object."],
  [0x00008000, "DF_1_DISPRELDNE", "Object has no displacement relocations."],
  [0x00010000, "DF_1_DISPRELPND", "Object has pending displacement relocations."],
  [0x00020000, "DF_1_NODIRECT", "Disable direct binding for this object."],
  [0x00040000, "DF_1_IGNMULDEF", "Reserved for internal runtime-linker use."],
  [0x00080000, "DF_1_NOKSYMS", "Reserved for internal runtime-linker use."],
  [0x00100000, "DF_1_NOHDR", "Reserved for internal runtime-linker use."],
  [0x00200000, "DF_1_EDITED", "Object has been modified after static link."],
  [0x00400000, "DF_1_NORELOC", "Reserved for internal runtime-linker use."],
  [0x00800000, "DF_1_SYMINTPOSE", "Interpose symbols from this object."],
  [0x01000000, "DF_1_GLOBAUDIT", "Enable global auditing hooks for this object."],
  [0x02000000, "DF_1_SINGLETON", "Singleton symbol semantics are required."],
  [0x04000000, "DF_1_STUB", "Stub-object marker (ABI/toolchain-specific)."],
  [0x08000000, "DF_1_PIE", "Object was built as position-independent executable (PIE)."],
  [0x10000000, "DF_1_KMOD", "Kernel runtime-linker marker (platform-specific)."],
  [0x20000000, "DF_1_WEAKFILTER", "Weak filter marker (platform/toolchain-specific)."],
  [0x40000000, "DF_1_NOCOMMON", "No-common-symbols marker (platform/toolchain-specific)."]
];
