import { aarch64Options } from "./aarch64-code.js";
import type { AnalyzeElfInstructionSetOptions } from "../../analyzers/elf/disassembly-types.js";
import type { AnalyzePeInstructionSetOptions } from "../../analyzers/pe/disassembly/types.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";

// NOP followed by data that resembles AVX or SVE code, then RET.
// LLVM MC AArch64 SVE/add.s; Intel SDM VADDPS (VEX.128.0F.WIG 58 /r).
export const isaDataBytes = (machine: number): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(32).fill(0x90);
  if (machine === 183 || machine === 0xaa64) {
    const view = new DataView(bytes.buffer);
    view.setUint32(0, 0xd503201f, true);
    view.setUint32(4, 0xd503201f, true);
    view.setUint32(8, 0x04a00000, true);
    view.setUint32(12, 0xd65f03c0, true);
  } else {
    bytes.set([0xc5, 0xf8, 0x58, 0xc0, 0xc3], 8);
  }
  const view = new DataView(bytes.buffer);
  // An init-array pointer into the middle of the known object is an independent code seed.
  if (machine === 3) view.setUint32(16, 0x100c, true);
  else view.setBigUint64(16, 0x100cn, true);
  return bytes;
};

export const elfIsaDataOptions = (machine: number): AnalyzeElfInstructionSetOptions => ({
  ...aarch64Options(16), machine, is64Bit: machine !== 3, fileType: 3,
  symbolTables: [{ sectionIndex: 2, issues: [], entries: [{ name: "_Z5value", info: 0x10,
    other: 0, sectionIndex: 1, value: 0x1008n, size: 8n }] }],
  sections: [{ index: 1, name: ".text", nameOff: 0, type: 1, typeName: "PROGBITS",
    flags: 6n, flagNames: ["ALLOC", "EXECINSTR"], addr: 0x1000n, offset: 0n, size: 16n,
    link: 0, info: 0, addralign: 4n, entsize: 0n },
  { index: 3, name: ".init_array", nameOff: 0, type: 14, typeName: "INIT_ARRAY", flags: 2n,
    flagNames: ["ALLOC"],
    addr: 0x2000n, offset: 16n, size: machine === 3 ? 4n : 8n,
    link: 0, info: 0, addralign: 4n, entsize: 0n }]
});

export const peIsaDataOptions = (machine: number): AnalyzePeInstructionSetOptions => ({
  coffMachine: machine, is64Bit: machine !== 0x14c, imageBase: 0x400000n,
  entrypointRva: 0x1000, dataRvas: [0x1008],
  exportRvas: [0x1008], unwindBeginRvas: [0x1008], tlsCallbackRvas: [0x1008],
  extraEntrypoints: [{ source: "pointer metadata", rvas: [0x1008] }],
  rvaToOff: rva => rva >= 0x1000 && rva < 0x1010 ? rva - 0x1000 : null,
  sections: [{ name: inlinePeSectionName(".text"), virtualAddress: 0x1000, virtualSize: 16,
    sizeOfRawData: 16, pointerToRawData: 0, characteristics: 0x20000020 }]
});
