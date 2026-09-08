// Processor relocation enumerations from LLVM (upstream ABI definitions):
// https://github.com/llvm/llvm-project/tree/main/llvm/include/llvm/BinaryFormat/ELFRelocs
import { ELF_MACHINE_ID } from "./abi-constants.js";

const names: Record<number, { prefix: string; types: Record<number, string> }> = {
  // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/i386.def
  [ELF_MACHINE_ID.I386]: { prefix: "R_386_", types: {
    0: "NONE", 1: "32", 2: "PC32", 3: "GOT32", 4: "PLT32", 5: "COPY",
    6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE", 9: "GOTOFF", 10: "GOTPC",
    14: "TLS_TPOFF", 35: "TLS_DTPMOD32", 36: "TLS_DTPOFF32", 37: "TLS_TPOFF32",
    41: "TLS_DESC", 42: "IRELATIVE", 43: "GOT32X"
  } },
  // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/x86_64.def
  [ELF_MACHINE_ID.X86_64]: { prefix: "R_X86_64_", types: {
    0: "NONE", 1: "64", 2: "PC32", 3: "GOT32", 4: "PLT32", 5: "COPY",
    6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE", 9: "GOTPCREL", 10: "32", 11: "32S",
    12: "16", 13: "PC16", 14: "8", 15: "PC8", 16: "DTPMOD64", 17: "DTPOFF64",
    18: "TPOFF64", 19: "TLSGD", 20: "TLSLD", 21: "DTPOFF32", 22: "GOTTPOFF",
    23: "TPOFF32", 24: "PC64", 25: "GOTOFF64", 26: "GOTPC32", 27: "GOT64",
    28: "GOTPCREL64", 29: "GOTPC64", 30: "GOTPLT64", 31: "PLTOFF64", 32: "SIZE32",
    33: "SIZE64", 34: "GOTPC32_TLSDESC", 35: "TLSDESC_CALL", 36: "TLSDESC",
    37: "IRELATIVE", 41: "GOTPCRELX", 42: "REX_GOTPCRELX"
  } },
  // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/AArch64.def
  [ELF_MACHINE_ID.AARCH64]: { prefix: "R_AARCH64_", types: {
    0: "NONE", 257: "ABS64", 258: "ABS32", 259: "ABS16", 260: "PREL64", 261: "PREL32",
    262: "PREL16", 275: "ADR_PREL_PG_HI21", 277: "ADD_ABS_LO12_NC", 282: "JUMP26",
    283: "CALL26", 311: "ADR_GOT_PAGE", 312: "LD64_GOT_LO12_NC", 1024: "COPY",
    1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE", 1028: "TLS_DTPMOD64",
    1029: "TLS_DTPREL64", 1030: "TLS_TPREL64", 1031: "TLSDESC", 1032: "IRELATIVE"
  } },
  // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/RISCV.def
  [ELF_MACHINE_ID.RISCV]: { prefix: "R_RISCV_", types: {
    0: "NONE", 1: "32", 2: "64", 3: "RELATIVE", 4: "COPY", 5: "JUMP_SLOT",
    6: "TLS_DTPMOD32", 7: "TLS_DTPMOD64", 8: "TLS_DTPREL32", 9: "TLS_DTPREL64",
    10: "TLS_TPREL32", 11: "TLS_TPREL64", 16: "BRANCH", 17: "JAL", 18: "CALL",
    19: "CALL_PLT", 20: "GOT_HI20", 51: "RELAX", 58: "IRELATIVE"
  } }
};

export const elfRelocationTypeName = (machine: number, type: number): string => {
  const architecture = names[machine];
  return architecture?.types[type] != null
    ? architecture.prefix + architecture.types[type]
    : `machine ${machine}, type ${type}`;
};
