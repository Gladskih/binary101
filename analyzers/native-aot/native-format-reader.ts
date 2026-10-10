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
export type NativeFormatLayout = "dotnet9" | "dotnet10";

export class NativeFormatReader {
  readonly #bytes: Uint8Array;
  readonly #view: DataView;
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });
  readonly #strings = new Map<number, { value: string } | { error: unknown }>();

  constructor(bytes: Uint8Array, readonly layout: NativeFormatLayout = "dotnet10") {
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

  uint8(offset: number): NativeFormatValue<number> {
    this.#requireRange(offset, 1);
    return { nextOffset: offset + 1, value: this.#view.getUint8(offset) };
  }

  float32(offset: number): NativeFormatValue<number> {
    this.#requireRange(offset, 4);
    return { nextOffset: offset + 4, value: this.#view.getFloat32(offset, true) };
  }

  float64(offset: number): NativeFormatValue<number> {
    this.#requireRange(offset, 8);
    return { nextOffset: offset + 8, value: this.#view.getFloat64(offset, true) };
  }

  unsigned64(offset: number): NativeFormatValue<string> {
    if ((this.uint8(offset).value & 31) !== 31) {
      const decoded = this.unsigned(offset);
      return { nextOffset: decoded.nextOffset, value: String(decoded.value) };
    }
    const decoded = this.#wideInteger(offset);
    return { nextOffset: decoded.nextOffset, value: String(decoded.value) };
  }

  signed64(offset: number): NativeFormatValue<string> {
    if ((this.uint8(offset).value & 31) !== 31) {
      const decoded = this.signed(offset);
      return { nextOffset: decoded.nextOffset, value: String(decoded.value) };
    }
    const decoded = this.#wideInteger(offset);
    return { nextOffset: decoded.nextOffset, value: String(BigInt.asIntN(64, decoded.value)) };
  }

  #wideInteger(offset: number): NativeFormatValue<bigint> {
    // DecodeUnsignedLong/DecodeSignedLong: 0b0_11111 introduces a little-endian UInt64.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Primitives.cs
    if (this.uint8(offset).value & 32) throw new NativeFormatError("Invalid compressed 64-bit integer.");
    this.#requireRange(offset + 1, 8);
    return { nextOffset: offset + 9, value: this.#view.getBigUint64(offset + 1, true) };
  }

  signed(offset: number): NativeFormatValue<number> {
    const decoded = this.unsigned(offset);
    // DecodeSigned uses a signed final byte in the 7/14/21/28-bit short forms.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
    const bits = Math.min(32, (decoded.nextOffset - offset) * 7);
    return { nextOffset: decoded.nextOffset, value: decoded.value << (32 - bits) >> (32 - bits) };
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
    // MdBinaryReader.Read(Handle): .NET 9 uses 8 tag bits; .NET 10 uses 7.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/MdBinaryReader.cs
    const tagBits = this.layout === "dotnet9" ? 8 : 7;
    const handle = permittedTypes.length === 1
      ? this.#typedHandle(decoded.value, permittedTypes[0]!)
      : { type: decoded.value & (2 ** tagBits - 1), offset: decoded.value >>> tagBits };
    if (handle.offset && !permittedTypes.includes(handle.type)) {
      throw new NativeFormatError(`Unexpected handle type ${handle.type}.`);
    }
    if (handle.offset >= this.size) {
      throw new NativeFormatError(`Handle offset ${handle.offset} is outside the metadata.`);
    }
    return { nextOffset: decoded.nextOffset, value: handle };
  }

  #typedHandle(value: number, expectedType: number): NativeFormatHandle {
    // Generated typed-handle constructors accept an untagged offset or their own tag.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
    // Generated typed handles use 24 offset bits in .NET 9 and 25 in .NET 10.
    const offsetBits = this.layout === "dotnet9" ? 24 : 25;
    const type = value >>> offsetBits;
    if (type !== 0 && type !== expectedType) {
      throw new NativeFormatError(`Unexpected typed handle type ${type}.`);
    }
    return { type: expectedType, offset: value & (2 ** offsetBits - 1) };
  }

  collectionCount(offset: number): NativeFormatValue<number> {
    const count = this.unsigned(offset);
    // Every compressed integer occupies at least one byte (DecodeUnsigned in the source above).
    this.#requireRange(count.nextOffset, count.value);
    return count;
  }

  handles(
    offset: number,
    permittedTypes: readonly number[]
  ): NativeFormatValue<NativeFormatHandle[]> {
    const count = this.collectionCount(offset);
    const values: NativeFormatHandle[] = [];
    let nextOffset = count.nextOffset;
    for (let index = 0; index < count.value; index += 1) {
      const decoded = this.handle(nextOffset, permittedTypes);
      if (decoded.value.offset) values.push(decoded.value);
      nextOffset = decoded.nextOffset;
    }
    return { nextOffset, value: values };
  }

  bytes(offset: number): NativeFormatValue<Uint8Array> {
    const count = this.collectionCount(offset);
    return {
      nextOffset: count.nextOffset + count.value,
      value: this.#bytes.subarray(count.nextOffset, count.nextOffset + count.value)
    };
  }

  string(handle: NativeFormatHandle): string {
    if (!handle.offset) return "";
    const cached = this.#strings.get(handle.offset);
    if (cached) {
      if ("error" in cached) throw cached.error;
      return cached.value;
    }
    try {
      const value = this.#decodeString(handle.offset);
      this.#strings.set(handle.offset, { value });
      return value;
    } catch (error) {
      this.#strings.set(handle.offset, { error });
      throw error;
    }
  }

  #decodeString(offset: number): string {
    const encoded = this.bytes(offset).value;
    try {
      return this.#decoder.decode(encoded);
    } catch {
      throw new NativeFormatError(`String at offset ${offset} is not valid UTF-8.`);
    }
  }

  #requireRange(offset: number, size: number): void {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 ||
      offset > this.size - size) {
      throw new NativeFormatError(`Range ${offset}+${size} is outside the metadata.`);
    }
  }
}
