export interface CrinklerTinyImport {
  dllNamesVa: number;
  tableVa: number;
  hashMultiplier: number;
  hashShift: number;
}

// Crinkler's import20_1k.asm starts with mov edi,_DLLNames and walks the loaded
// modules. The fixed opcodes below surround the relocatable operands in that stub.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/import20_1k.asm
const stub = {
  walkModules: { offset: 5, bytes: [0x58, 0x8b, 0x40, 0x0c, 0x8b, 0x40, 0x0c,
    0x8b, 0x40, 0x00, 0x8b, 0x40, 0x00, 0x8b, 0x40, 0x18] },
  hashName: { offset: 0x41, bytes: [0xac, 0x69, 0xc0] }, // lodsb / imul eax, imm32
  finishHash: { offset: 0x48, bytes: [0x00, 0xc0, 0x75, 0xf5, 0xc1, 0xe8] },
  storeSlot: { offset: 0x4f, bytes: [0x89, 0x14, 0x85] }, // mov [eax*4 + imm32], edx
  callLoader: { offset: 0x56, bytes: [0x41, 0x3b, 0x4b, 0x18, 0x75, 0xc6, 0x57, 0xff, 0x15] },
  continueDllLoop: { offset: 0x66, bytes: [0x85, 0xc0, 0x75, 0xab] }
};

const matchesImportStub = (data: Uint8Array): boolean =>
  // mov edi, imm32 precedes the module-list walk.
  data[0] === 0xbf && Object.values(stub).every(({ offset, bytes }) =>
    bytes.every((byte, index) => byte === data[offset + index]));

export const readCrinklerTinyImport = (data: Uint8Array): CrinklerTinyImport | null => {
  if (!matchesImportStub(data)) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const hashShift = view.getUint8(stub.finishHash.offset + stub.finishHash.bytes.length);
  // x86 masks the SHR count to five bits for a 32-bit destination.
  if (hashShift >= Uint32Array.BYTES_PER_ELEMENT * 8) return null;
  return {
    dllNamesVa: view.getUint32(1, true),
    tableVa: view.getUint32(stub.storeSlot.offset + stub.storeSlot.bytes.length, true),
    hashMultiplier: view.getUint32(stub.hashName.offset + stub.hashName.bytes.length, true),
    hashShift
  };
};
