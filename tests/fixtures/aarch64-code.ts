import type { AnalyzeElfInstructionSetOptions } from "../../analyzers/elf/disassembly-types.js";
import { MockFile } from "../helpers/mock-file.js";

// Encodings: https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/test/decode.test.mjs
// SVE add: https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/llvm/test/MC/AArch64/SVE/add.s
export const aarch64Code = (words: number[]): MockFile => {
  const bytes = new Uint8Array(words.length * 4);
  const view = new DataView(bytes.buffer);
  words.forEach((word, index) => view.setUint32(index * 4, word, true));
  return new MockFile(bytes, "aarch64.elf");
};

export const aarch64Options = (size: number): AnalyzeElfInstructionSetOptions => ({
  // AAELF64: EM_AARCH64 = 183; PT_LOAD = 1, PF_X = 1.
  machine: 183,
  is64Bit: true,
  littleEndian: true,
  entrypointVaddr: 0x1000n,
  programHeaders: [{
    index: 0, type: 1, typeName: "PT_LOAD", flags: 1, flagNames: ["PF_X"],
    offset: 0n, vaddr: 0x1000n, paddr: 0x1000n,
    filesz: BigInt(size), memsz: BigInt(size), align: 4n
  }],
  sections: []
});
