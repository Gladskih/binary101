import type { FileRangeReader } from "../file-range-reader.js";

// Bounded LEB128 cursor for APS2 and CREL. The 64-bit limit is the ELF word
// limit, not a relocation-count or payload-size heuristic.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/Object/ELF.h
export class ElfRelocationStream {
  position: number;
  readonly end: number;
  constructor(readonly reader: FileRangeReader, offset: number, size: number) {
    this.position = offset;
    this.end = offset + size;
  }
  async byte(): Promise<number> {
    if (this.position >= this.end) throw new Error("truncated packed relocation stream");
    const view = await this.reader.read(this.position++, 1);
    if (!view.byteLength) throw new Error("truncated packed relocation read");
    return view.getUint8(0);
  }
  async unsigned(): Promise<bigint> {
    let value = 0n;
    for (let shift = 0n; shift < 64n; shift += 7n) {
      const byte = await this.byte();
      value |= BigInt(byte & 0x7f) << shift;
      if (!(byte & 0x80)) {
        if (value >= 1n << 64n) break;
        return value;
      }
    }
    throw new Error("packed relocation ULEB128 overflows 64 bits");
  }
  async signed(): Promise<bigint> {
    let value = 0n;
    for (let shift = 0n; shift < 64n; shift += 7n) {
      const byte = await this.byte();
      value |= BigInt(byte & 0x7f) << shift;
      if (!(byte & 0x80)) {
        const result = byte & 0x40 ? value - (1n << (shift + 7n)) : value;
        if (BigInt.asIntN(64, result) !== result) break;
        return result;
      }
    }
    throw new Error("packed relocation SLEB128 overflows 64 bits");
  }
}
