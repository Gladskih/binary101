"use strict";

// Encoding and handle rules are defined by dotnet/runtime's NativeFormat reader:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs

export interface NativeFormatHandle {
  type: number;
  offset: number;
}

export interface NativeFormatValue<T> {
  nextOffset: number;
  value: T;
}

export class NativeFormatError extends Error {}

const MAX_STRING_BYTES = 1024 * 1024;

export class NativeFormatReader {
  readonly #bytes: Uint8Array;
  readonly #view: DataView;
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get size(): number {
    return this.#bytes.byteLength;
  }

  uint32(offset: number): number {
    this.#requireRange(offset, 4);
    return this.#view.getUint32(offset, true);
  }

  unsigned(offset: number): NativeFormatValue<number> {
    this.#requireRange(offset, 1);
    const first = this.#bytes[offset]!;
    if ((first & 1) === 0) return { nextOffset: offset + 1, value: first >>> 1 };
    if ((first & 2) === 0) {
      this.#requireRange(offset, 2);
      return {
        nextOffset: offset + 2,
        value: (first >>> 2) | (this.#bytes[offset + 1]! << 6)
      };
    }
    if ((first & 4) === 0) {
      this.#requireRange(offset, 3);
      return {
        nextOffset: offset + 3,
        value: (first >>> 3) | (this.#bytes[offset + 1]! << 5) |
          (this.#bytes[offset + 2]! << 13)
      };
    }
    if ((first & 8) === 0) {
      this.#requireRange(offset, 4);
      return {
        nextOffset: offset + 4,
        value: ((first >>> 4) | (this.#bytes[offset + 1]! << 4) |
          (this.#bytes[offset + 2]! << 12) | (this.#bytes[offset + 3]! << 20)) >>> 0
      };
    }
    if ((first & 16) !== 0) throw new NativeFormatError("Invalid compressed integer.");
    this.#requireRange(offset, 5);
    return { nextOffset: offset + 5, value: this.#view.getUint32(offset + 1, true) };
  }

  handle(offset: number, permittedTypes: readonly number[]): NativeFormatValue<NativeFormatHandle> {
    const decoded = this.unsigned(offset);
    const handle = permittedTypes.length === 1
      ? { type: permittedTypes[0]!, offset: decoded.value }
      : { type: decoded.value & 0x7f, offset: decoded.value >>> 7 };
    if (handle.offset && !permittedTypes.includes(handle.type)) {
      throw new NativeFormatError(`Unexpected handle type ${handle.type}.`);
    }
    if (handle.offset >= this.size) {
      throw new NativeFormatError(`Handle offset ${handle.offset} is outside the metadata.`);
    }
    return { nextOffset: decoded.nextOffset, value: handle };
  }

  handles(
    offset: number,
    permittedTypes: readonly number[],
    maximumCount: number
  ): NativeFormatValue<NativeFormatHandle[]> {
    const count = this.unsigned(offset);
    if (count.value > maximumCount) {
      throw new NativeFormatError(`Collection count ${count.value} exceeds the safety limit.`);
    }
    const values: NativeFormatHandle[] = [];
    let nextOffset = count.nextOffset;
    for (let index = 0; index < count.value; index += 1) {
      const decoded = this.handle(nextOffset, permittedTypes);
      if (decoded.value.offset) values.push(decoded.value);
      nextOffset = decoded.nextOffset;
    }
    return { nextOffset, value: values };
  }

  bytes(offset: number, maximumCount: number): NativeFormatValue<Uint8Array> {
    const count = this.unsigned(offset);
    if (count.value > maximumCount) {
      throw new NativeFormatError(`Byte collection size ${count.value} exceeds the safety limit.`);
    }
    this.#requireRange(count.nextOffset, count.value);
    return {
      nextOffset: count.nextOffset + count.value,
      value: this.#bytes.subarray(count.nextOffset, count.nextOffset + count.value)
    };
  }

  string(handle: NativeFormatHandle): string {
    if (!handle.offset) return "";
    const encoded = this.bytes(handle.offset, MAX_STRING_BYTES).value;
    try {
      return this.#decoder.decode(encoded);
    } catch {
      throw new NativeFormatError(`String at offset ${handle.offset} is not valid UTF-8.`);
    }
  }

  #requireRange(offset: number, size: number): void {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 ||
      offset > this.size - size) {
      throw new NativeFormatError(`Range ${offset}+${size} is outside the metadata.`);
    }
  }
}
