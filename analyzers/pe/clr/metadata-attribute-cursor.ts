"use strict";

import { readCompressedUInt } from "./metadata-heaps.js";

// ECMA-335 II.23.3 defines CustomAttrib serialization, SerString, and named-argument tags.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
export const NAMED_ARGUMENT_FIELD_TAG = 0x53;
export const NAMED_ARGUMENT_PROPERTY_TAG = 0x54;
export const BYTE_WIDTH_U8 = Uint8Array.BYTES_PER_ELEMENT;
export const BYTE_WIDTH_U16 = Uint16Array.BYTES_PER_ELEMENT;
export const BYTE_WIDTH_U32 = Uint32Array.BYTES_PER_ELEMENT;
export const BYTE_WIDTH_U64 = BigUint64Array.BYTES_PER_ELEMENT;
export const BYTE_WIDTH_F32 = Float32Array.BYTES_PER_ELEMENT;
export const BYTE_WIDTH_F64 = Float64Array.BYTES_PER_ELEMENT;

const isFieldOrPropertyTypeStart = (elementType: number | undefined): boolean => {
  // ECMA-335 II.23.3 FieldOrPropType starts with an ELEMENT_TYPE simple type, Type,
  // boxed object, SZARRAY, or enum marker.
  switch (elementType) {
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x0e:
    case 0x1d:
    case 0x50:
    case 0x51:
    case 0x55:
      return true;
    default:
      return false;
  }
};

export class AttributeCursor {
  offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly issues: string[],
    private readonly context: string
  ) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  get issueCount(): number {
    return this.issues.length;
  }

  readU8(): number | null {
    const value = this.bytes[this.offset];
    if (value == null) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    this.offset += BYTE_WIDTH_U8;
    return value;
  }

  readU16(): number | null {
    if (this.remaining < BYTE_WIDTH_U16) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, BYTE_WIDTH_U16)
      .getUint16(0, true);
    this.offset += BYTE_WIDTH_U16;
    return value;
  }

  readU32(): number | null {
    if (this.remaining < BYTE_WIDTH_U32) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, BYTE_WIDTH_U32)
      .getUint32(0, true);
    this.offset += BYTE_WIDTH_U32;
    return value;
  }

  readF32(): number | null {
    if (this.remaining < BYTE_WIDTH_F32) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, BYTE_WIDTH_F32)
      .getFloat32(0, true);
    this.offset += BYTE_WIDTH_F32;
    return value;
  }

  readF64(): number | null {
    if (this.remaining < BYTE_WIDTH_F64) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, BYTE_WIDTH_F64)
      .getFloat64(0, true);
    this.offset += BYTE_WIDTH_F64;
    return value;
  }

  hasEnumValueBoundary(byteLength: number, remainingNamedArgumentCount: number): boolean {
    if (this.remaining < byteLength) return false;
    if (remainingNamedArgumentCount === 0) return this.remaining === byteLength;
    const nextKindByte = this.bytes[this.offset + byteLength];
    const nextTypeByte = this.bytes[this.offset + byteLength + BYTE_WIDTH_U8];
    return (
      nextKindByte === NAMED_ARGUMENT_FIELD_TAG ||
      nextKindByte === NAMED_ARGUMENT_PROPERTY_TAG
    ) && isFieldOrPropertyTypeStart(nextTypeByte);
  }

  hasTrailingNamedCountAfter(byteLength: number): boolean {
    if (this.remaining < byteLength + BYTE_WIDTH_U16) return false;
    const namedCount = new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset + this.offset + byteLength,
      BYTE_WIDTH_U16
    ).getUint16(0, true);
    if (namedCount === 0) return this.remaining === byteLength + BYTE_WIDTH_U16;
    const firstNamedKind = this.bytes[this.offset + byteLength + BYTE_WIDTH_U16];
    const firstNamedType = this.bytes[this.offset + byteLength + BYTE_WIDTH_U16 + BYTE_WIDTH_U8];
    return (
      firstNamedKind === NAMED_ARGUMENT_FIELD_TAG ||
      firstNamedKind === NAMED_ARGUMENT_PROPERTY_TAG
    ) && isFieldOrPropertyTypeStart(firstNamedType);
  }

  readSerString(): string | null {
    if (this.remaining < BYTE_WIDTH_U8) {
      this.issues.push(`${this.context} custom attribute string is truncated.`);
      return null;
    }
    // ECMA-335 II.23.3: a SerString byte value of 0xff encodes null.
    if (this.bytes[this.offset] === 0xff) {
      this.offset += BYTE_WIDTH_U8;
      return null;
    }
    const length = readCompressedUInt(this.bytes, this.offset);
    if (!length) {
      this.issues.push(`${this.context} custom attribute string length is malformed.`);
      return null;
    }
    this.offset += length.size;
    if (this.remaining < length.value) {
      this.issues.push(`${this.context} custom attribute string extends past the blob.`);
      return null;
    }
    const text = new TextDecoder("utf-8", { fatal: false })
      .decode(this.bytes.subarray(this.offset, this.offset + length.value));
    this.offset += length.value;
    return text;
  }

  addIssue(message: string): void {
    this.issues.push(`${this.context} ${message}`);
  }
}
