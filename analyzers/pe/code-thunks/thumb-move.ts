// Shared MOVW/MOVT decoding for PE code thunks. Both MSVC imports and ReadyToRun
// materialize a 32-bit address with this pair; interpretation of the result belongs to each ABI.
// https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp#L156
export const readThumbMovePair = (view: DataView, offset: number, register: number): number | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + 8 > view.byteLength ||
      !Number.isInteger(register) || register < 0 || register > 15) return null;
  if (![[0, 0xf240, 0xfbf0], [2, register << 8, 0x8f00],
    [4, 0xf2c0, 0xfbf0], [6, register << 8, 0x8f00]].every(
    ([position, word, mask]) => (view.getUint16(offset + position!, true) & mask!) === word)) return null;
  return readImmediate(view, offset) + readImmediate(view, offset + 4) * 65536;
};

const readImmediate = (view: DataView, offset: number): number =>
  ((view.getUint16(offset, true) & 0xf) << 12) |
  ((view.getUint16(offset, true) & 0x400) << 1) |
  ((view.getUint16(offset + 2, true) & 0x7000) >>> 4) | (view.getUint16(offset + 2, true) & 0xff);
