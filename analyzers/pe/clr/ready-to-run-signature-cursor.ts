import { readCompressedUInt } from "./metadata-heaps.js";

// R2R signatures use ECMA-style high-bit integer tags, unlike NativeFormat entrypoints.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunSignature.cs
export class ReadyToRunSignatureCursor {
  readonly #bytes: Uint8Array;
  offset: number;

  constructor(bytes: Uint8Array, offset: number) {
    this.#bytes = bytes;
    this.offset = offset;
  }

  byte(): number {
    if (!Number.isSafeInteger(this.offset) || this.offset < 0 || this.offset >= this.#bytes.length) {
      throw new Error("R2R signature is truncated or out of bounds.");
    }
    return this.#bytes[this.offset++]!;
  }

  peek(): number | null { return this.#bytes[this.offset] ?? null; }

  unsigned(): number {
    if (!Number.isSafeInteger(this.offset)) throw new Error("Invalid R2R signature offset.");
    const value = readCompressedUInt(this.#bytes, this.offset);
    if (!value) throw new Error("R2R signature has a malformed compressed integer.");
    this.offset += value.size;
    return value.value;
  }

  count(): number {
    const count = this.unsigned();
    if (count > this.#bytes.length - this.offset) {
      throw new Error("R2R signature count exceeds its remaining bytes.");
    }
    return count;
  }
}
