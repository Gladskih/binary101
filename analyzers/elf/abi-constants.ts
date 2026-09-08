// Numeric identifiers from the ELF gABI. Keeping them here prevents format-specific
// numbers from becoming unexplained conditions in the table walkers.
// https://gabi.xinuos.com/elf/02-eheader.html (e_type, e_machine)
export const ELF_FILE_TYPE = { REL: 1, EXEC: 2, DYN: 3 } as const;
export const ELF_MACHINE_ID = { I386: 3, MIPS: 8, X86_64: 62, AARCH64: 183, RISCV: 243 } as const;

// https://gabi.xinuos.com/elf/03-sheader.html (sh_type, sh_flags)
export const ELF_SECTION_TYPE = {
  SYMTAB: 2, STRTAB: 3, RELA: 4, DYNAMIC: 6, NOBITS: 8, REL: 9, DYNSYM: 11,
  SYMTAB_SHNDX: 18, RELR: 19
} as const;
export const ELF_SECTION_FLAG = { ALLOC: 0x2n } as const;

// https://gabi.xinuos.com/elf/07-pheader.html (p_type)
export const ELF_SEGMENT_TYPE = { LOAD: 1, DYNAMIC: 2 } as const;

// https://gabi.xinuos.com/elf/08-dynamic.html (d_tag)
// GNU prefix count tags: https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
export const ELF_DYNAMIC_TAG = {
  NULL: 0, PLTRELSZ: 2, HASH: 4, STRTAB: 5, SYMTAB: 6, RELA: 7, RELASZ: 8, RELAENT: 9,
  STRSZ: 10, SYMENT: 11, REL: 17, RELSZ: 18, RELENT: 19, PLTREL: 20, JMPREL: 23,
  RELRSZ: 35, RELR: 36, RELRENT: 37, RELACOUNT: 0x6ffffff9, RELCOUNT: 0x6ffffffa
} as const;

// https://gabi.xinuos.com/elf/05-symtab.html: SHN_XINDEX and Elf32_Word SHNDX entries.
// https://gabi.xinuos.com/elf/06-reloc.html: ELF64_R_SYM occupies at most 32 bits.
export const ELF_SYMBOL_INDEX = { UNDEF: 0, XINDEX: 0xffff, MAX: 0xffff_ffff, BYTE_SIZE: 4 } as const;

// Relative types from the processor ABI enumerations in LLVM's ELFRelocs headers:
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/x86_64.def
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/AArch64.def
export const ELF_RELATIVE_TYPE = { X86_64: 8, AARCH64: 1027 } as const;
