"use strict";

import { decodeMetadataUtf8 } from "./metadata-utf8.js";

export interface ClrCompressedUInt {
  value: number;
  size: number;
}

export interface ClrMetadataHeapData {
  strings: Uint8Array | null;
  guid: Uint8Array | null;
  blob: Uint8Array | null;
  userString: Uint8Array | null;
}

export const readCompressedUInt = (
  bytes: Uint8Array,
  offset: number
): ClrCompressedUInt | null => {
  // ECMA-335 II.23.2: PackedLen uses 1, 2, or 4 bytes with high-bit tag patterns.
  if (offset < 0 || offset >= bytes.length) return null;
  const first = bytes[offset];
  if (first == null) return null;
  if ((first & 0x80) === 0) return { value: first, size: 1 };
  if ((first & 0xc0) === 0x80) {
    const second = bytes[offset + 1];
    if (second == null) return null;
    return { value: ((first & 0x3f) << 8) | second, size: 2 };
  }
  if ((first & 0xe0) === 0xc0) {
    return readFourByteCompressedUInt(bytes, offset, first);
  }
  return null;
};

const readFourByteCompressedUInt = (
  bytes: Uint8Array,
  offset: number,
  first: number
): ClrCompressedUInt | null => {
  if (offset + 4 > bytes.length) return null;
  return {
    value: ((first & 0x1f) << 24) | (bytes[offset + 1]! << 16) |
      (bytes[offset + 2]! << 8) | bytes[offset + 3]!,
    size: 4
  };
};

const toHexByte = (byteValue: number): string => byteValue.toString(16).padStart(2, "0");

const formatGuid = (bytes: Uint8Array, offset: number): string => {
  // ECMA-335 II.24.2.5 stores GUID heap entries as 16-byte GUID values.
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 16);
  const head = [
    view.getUint32(0, true).toString(16).padStart(8, "0"),
    view.getUint16(4, true).toString(16).padStart(4, "0"),
    view.getUint16(6, true).toString(16).padStart(4, "0")
  ];
  const tail = [
    `${toHexByte(view.getUint8(8))}${toHexByte(view.getUint8(9))}`,
    Array.from({ length: 6 }, (_, index) => toHexByte(view.getUint8(10 + index))).join("")
  ];
  return [...head, ...tail].join("-");
};

export class ClrHeapReaders {
  private readonly stringCache = new Map<number, string | null>();
  private readonly guidCache = new Map<number, string | null>();
  private readonly blobCache = new Map<number, Uint8Array | null>();
  private readonly decodedBlobCache = new Map<
    (bytes: Uint8Array | null, context: string) => unknown, Map<number, unknown>
  >();

  constructor(
    private readonly heaps: ClrMetadataHeapData,
    readonly issues: string[]
  ) {}

  getString(index: number, context: string): string | null {
    const cached = this.stringCache.get(index);
    if (cached !== undefined) return cached;
    const value = this.readString(index, context);
    this.stringCache.set(index, value);
    return value;
  }

  getGuid(index: number, context: string): string | null {
    const cached = this.guidCache.get(index);
    if (cached !== undefined) return cached;
    const value = this.readGuid(index, context);
    this.guidCache.set(index, value);
    return value;
  }

  getBlob(index: number, context: string): Uint8Array | null {
    const cached = this.blobCache.get(index);
    if (cached !== undefined) return cached;
    const value = this.readBlob(index, context);
    this.blobCache.set(index, value);
    return value;
  }

  getBlobSize(index: number, context: string): number | null {
    return this.getBlob(index, context)?.length ?? null;
  }

  decodeBlob<Value>(
    index: number,
    context: string,
    decode: (bytes: Uint8Array | null, context: string) => Value
  ): Value {
    const entries = this.decodedBlobCache.get(decode) ?? new Map<number, unknown>();
    if (entries.has(index)) return entries.get(index) as Value;
    // Share interpretations within this parse, including absent blobs and undefined results.
    const value = decode(this.getBlob(index, context), context);
    entries.set(index, value);
    this.decodedBlobCache.set(decode, entries);
    return value;
  }

  private readString(index: number, context: string): string | null {
    if (index === 0) return "";
    if (!this.heaps.strings) {
      this.issues.push(`${context} references #Strings, but the heap is absent.`);
      return null;
    }
    if (index < 0 || index >= this.heaps.strings.length) {
      this.issues.push(`${context} has #Strings index ${index}, outside the heap.`);
      return null;
    }
    const terminator = this.heaps.strings.indexOf(0, index);
    const end = terminator === -1 ? this.heaps.strings.length : terminator;
    if (terminator === -1) {
      this.issues.push(`${context} string at #Strings index ${index} is not null-terminated.`);
    }
    return decodeMetadataUtf8(this.heaps.strings.subarray(index, end), this.issues, context);
  }

  private readGuid(index: number, context: string): string | null {
    if (index === 0) return null;
    if (!this.heaps.guid) {
      this.issues.push(`${context} references #GUID, but the heap is absent.`);
      return null;
    }
    const offset = (index - 1) * 16;
    if (offset < 0 || offset + 16 > this.heaps.guid.length) {
      this.issues.push(`${context} has #GUID index ${index}, outside the heap.`);
      return null;
    }
    return formatGuid(this.heaps.guid, offset);
  }

  private readBlob(index: number, context: string): Uint8Array | null {
    if (index === 0) return new Uint8Array(0);
    if (!this.heaps.blob) {
      this.issues.push(`${context} references #Blob, but the heap is absent.`);
      return null;
    }
    if (index < 0 || index >= this.heaps.blob.length) {
      this.issues.push(`${context} has #Blob index ${index}, outside the heap.`);
      return null;
    }
    const length = readCompressedUInt(this.heaps.blob, index);
    if (!length) {
      this.issues.push(`${context} has a malformed compressed length in #Blob.`);
      return null;
    }
    const start = index + length.size;
    if (start + length.value > this.heaps.blob.length) {
      this.issues.push(`${context} blob at #Blob index ${index} extends past the heap.`);
      return null;
    }
    return this.heaps.blob.subarray(start, start + length.value);
  }
}
