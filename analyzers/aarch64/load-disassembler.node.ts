import { createDisassembler } from "llvm-aarch64-disasm";

export const loadAarch64Disassembler = async () => createDisassembler();
