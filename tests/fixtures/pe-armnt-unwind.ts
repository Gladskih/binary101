import { MockFile } from "../helpers/mock-file.js";

export const ARMNT_FIXTURE_XDATA_RVA = 96;

// Microsoft ARM packed unwind: Ret=16-bit branch; R=1, Reg=7 means no saved registers.
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling#packed-unwind-data
export const armntPackedWord = (length = 4, flag = 1): number =>
  ((length / 2) << 2) | flag | (1 << 13) | (7 << 16) | (1 << 19);

export const createArmntXdata = (header: number, size = 32, extension = 0, handler = 0): MockFile => {
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  if (size >= 12) view.setUint32(8, header, true);
  if (size >= 16) view.setUint32(12, extension, true);
  if (handler) view.setUint32(size - 4, handler, true);
  const extended = (header >>> 23) === 0;
  const scopeCount = extended ? extension & 0xffff : (header >>> 23) & 31;
  const codeWords = extended ? (extension >>> 16) & 255 : header >>> 28;
  const codeOffset = (extended ? 8 : 4) + ((header & (1 << 21)) !== 0 ? 0 : scopeCount * 4);
  if ((header & (1 << 21)) === 0) {
    for (let index = 0; index < scopeCount && 8 + (extended ? 8 : 4) + index * 4 + 4 <= size; index += 1) {
      view.setUint32(8 + (extended ? 8 : 4) + index * 4, index, true);
    }
  }
  bytes.fill(0xff, 8 + codeOffset, Math.min(size - (handler ? 4 : 0), 8 + codeOffset + codeWords * 4));
  return new MockFile(bytes);
};

export const createArmntTable = (words: readonly number[]) => {
  const code = 64;
  const bytes = new Uint8Array(128);
  const table = new Uint8Array(words.length * 8);
  const view = new DataView(table.buffer);
  words.forEach((word, index) => {
    view.setUint32(index * 8, code + index * 4 + 1, true);
    view.setUint32(index * 8 + 4, word, true);
  });
  bytes.set(table, 16);
  new DataView(bytes.buffer).setUint32(ARMNT_FIXTURE_XDATA_RVA, 2 | (1 << 28), true);
  bytes.fill(0xff, ARMNT_FIXTURE_XDATA_RVA + 4, ARMNT_FIXTURE_XDATA_RVA + 8);
  return { file: new MockFile(bytes), source: new MockFile(table), code, xdata: ARMNT_FIXTURE_XDATA_RVA,
    directory: { name: "EXCEPTION", rva: 16, size: table.length } };
};
