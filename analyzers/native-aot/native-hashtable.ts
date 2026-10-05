import { NativeFormatError, NativeFormatReader } from "./native-format-reader.js";

// Header, bucket offsets and signed entry-relative references follow NativeHashtable.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/NativeHashtable.cs
export class NativeHashtableReader {
  readonly #reader: NativeFormatReader;
  readonly #view: DataView;
  readonly #width: number;
  readonly #bucketCount: number;

  constructor(bytes: Uint8Array) {
    this.#reader = new NativeFormatReader(bytes);
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const header = this.#reader.uint8(0).value;
    if ((header >>> 2) > 31 || (header & 3) > 2) {
      throw new NativeFormatError("Invalid NativeHashtable header.");
    }
    this.#width = 2 ** (header & 3);
    this.#bucketCount = 2 ** (header >>> 2);
    if ((this.#bucketCount + 1) * this.#width > bytes.length - 1) {
      throw new NativeFormatError("NativeHashtable bucket index is truncated.");
    }
  }

  #index(bucket: number): number {
    const offset = 1 + bucket * this.#width;
    if (this.#width === 1) return 1 + this.#view.getUint8(offset);
    if (this.#width === 2) return 1 + this.#view.getUint16(offset, true);
    return 1 + this.#view.getUint32(offset, true);
  }

  *#bucket(start: number, end: number): Generator<{ offset: number; lowHashcode: number }> {
    if (start > end ||
      start < 1 + (this.#bucketCount + 1) * this.#width) {
      throw new NativeFormatError("NativeHashtable bucket range is invalid.");
    }
    for (let position = start; position < end;) {
      const lowHashcode = this.#reader.uint8(position).value;
      const reference = this.#reader.signed(position + 1);
      const target = position + 1 + reference.value;
      if (reference.nextOffset > end || target < 0 || target >= this.#reader.size) {
        throw new NativeFormatError("NativeHashtable entry reference is truncated or out of bounds.");
      }
      yield { offset: target, lowHashcode };
      position = reference.nextOffset;
    }
  }

  *entries(issues: Set<string>): Generator<{ offset: number; lowHashcode: number }> {
    for (let bucket = 0; bucket < this.#bucketCount; bucket += 1) {
      try {
        const end = this.#index(bucket + 1);
        if (end > this.#reader.size) issues.add("NativeHashtable bucket data is truncated.");
        yield* this.#bucket(this.#index(bucket), Math.min(end, this.#reader.size));
      } catch (error) {
        issues.add(error instanceof Error ? error.message : "NativeHashtable decoding failed.");
      }
    }
  }
}
