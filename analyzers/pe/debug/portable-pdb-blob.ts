import { readCompressedUInt } from "../clr/metadata-heaps.js";

// Portable PDB uses ECMA-335 II.23.2 compressed integers, fixed little-endian values
// and terminated UTF-8 strings. Internal failures are caught at each record boundary.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
export class PortablePdbBlobReader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  get remaining(): number { return this.bytes.length - this.offset; }
  take(size: number): Uint8Array {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.remaining) {
      throw new Error("blob is truncated or has an invalid size");
    }
    const start = this.offset;
    this.offset += size;
    return this.bytes.subarray(start, this.offset);
  }
  byte(): number { return this.take(1)[0]!; }
  uint32(): number {
    const bytes = this.take(4);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getUint32(0, true);
  }
  int32(): number {
    const bytes = this.take(4);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getInt32(0, true);
  }
  compressed(): number {
    const result = readCompressedUInt(this.bytes, this.offset);
    if (!result) throw new Error("compressed integer is malformed or truncated");
    this.offset += result.size;
    return result.value;
  }
  signed(): number {
    const start = this.offset;
    const value = this.compressed();
    const bits = ({ 1: 6, 2: 13, 4: 28 } as Record<number, number>)[this.offset - start]!;
    return (value >>> 1) - ((value & 1) ? 2 ** bits : 0);
  }
  count(): number {
    const count = this.compressed();
    if (count > this.remaining) throw new Error("item count exceeds the remaining bytes");
    return count;
  }
  utf8z(): string {
    const end = this.bytes.indexOf(0, this.offset);
    if (end < 0) throw new Error("UTF-8 string is not NUL-terminated");
    const bytes = this.take(end - this.offset + 1);
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, -1));
  }
  finish(): void {
    if (this.remaining) throw new Error("blob has trailing bytes");
  }
}
