"use strict";

import type {
  PeClrCustomAttributeArgument,
  PeClrCustomAttributeNamedArgument
} from "./types.js";
import { readCompressedUInt } from "./metadata-heaps.js";

// ECMA-335 II.23.3 defines the serialized CustomAttrib blob and named argument tags.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
interface DecodedCustomAttributeValue {
  fixedArguments: PeClrCustomAttributeArgument[];
  namedArguments: PeClrCustomAttributeNamedArgument[];
  issues?: string[];
}

interface ReadValueResult {
  value: string | number | boolean | null;
  complete: boolean;
}

interface ReadFixedArgumentResult {
  argument: PeClrCustomAttributeArgument;
  complete: boolean;
}

class AttributeCursor {
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
    this.offset += 1;
    return value;
  }

  readU16(): number | null {
    if (this.remaining < 2) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 2)
      .getUint16(0, true);
    this.offset += 2;
    return value;
  }

  readU32(): number | null {
    if (this.remaining < 4) {
      this.issues.push(`${this.context} custom attribute blob is truncated.`);
      return null;
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4)
      .getUint32(0, true);
    this.offset += 4;
    return value;
  }

  readSerString(): string | null {
    if (this.remaining < 1) {
      this.issues.push(`${this.context} custom attribute string is truncated.`);
      return null;
    }
    if (this.bytes[this.offset] === 0xff) {
      this.offset += 1;
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

const readWithIssueStatus = (
  cursor: AttributeCursor,
  readValue: () => string | number | boolean | null
): ReadValueResult => {
  const issueCount = cursor.issueCount;
  return { value: readValue(), complete: cursor.issueCount === issueCount };
};

const readPrimitive = (cursor: AttributeCursor, type: string | null): ReadValueResult => {
  if (type === "string" || type === "System.Type") {
    return readWithIssueStatus(cursor, () => cursor.readSerString());
  }
  if (type === "bool") return readWithIssueStatus(cursor, () => (cursor.readU8() ?? 0) !== 0);
  if (type === "char") {
    return readWithIssueStatus(cursor, () => {
      const value = cursor.readU16();
      return value == null ? null : String.fromCharCode(value);
    });
  }
  if (type === "i1" || type === "u1") return readWithIssueStatus(cursor, () => cursor.readU8());
  if (type === "i2" || type === "u2") return readWithIssueStatus(cursor, () => cursor.readU16());
  if (type === "i4" || type === "u4") return readWithIssueStatus(cursor, () => cursor.readU32());
  if (type === "i8" || type === "u8") {
    return readWithIssueStatus(cursor, () => {
      const low = cursor.readU32();
      const high = cursor.readU32();
      return low == null || high == null
        ? null
        : `0x${high.toString(16)}${low.toString(16).padStart(8, "0")}`;
    });
  }
  cursor.addIssue(`fixed argument type "${type ?? "unknown"}" is not supported; decoding stopped.`);
  return { value: null, complete: false };
};

const elementTypeName = (elementType: number): string | null => {
  const names: Record<number, string> = {
    0x02: "bool",
    0x03: "char",
    0x04: "i1",
    0x05: "u1",
    0x06: "i2",
    0x07: "u2",
    0x08: "i4",
    0x09: "u4",
    0x0a: "i8",
    0x0b: "u8",
    0x0e: "string",
    0x50: "System.Type",
    0x51: "object"
  };
  return names[elementType] || null;
};

const readFieldOrPropType = (cursor: AttributeCursor): string | null => {
  const elementType = cursor.readU8();
  if (elementType == null) return null;
  if (elementType === 0x55) return `enum ${cursor.readSerString() || "?"}`;
  if (elementType === 0x1d) return `${readFieldOrPropType(cursor) || "?"}[]`;
  return elementTypeName(elementType) || `ELEMENT_TYPE_${elementType.toString(16).padStart(2, "0")}`;
};

const readFixedArgument = (
  cursor: AttributeCursor,
  type: string | null
): ReadFixedArgumentResult => {
  if (type?.endsWith("[]")) {
    const count = cursor.readU32();
    if (count == null || count === 0xffffffff) {
      return { argument: { type, value: null }, complete: true };
    }
    const values: Array<string | number | boolean | null> = [];
    for (let index = 0; index < count; index += 1) {
      if (cursor.remaining <= 0) {
        cursor.addIssue(`array argument "${type}" is truncated after ${index}/${count} element(s).`);
        return { argument: { type, value: values.map(String).join(", ") }, complete: false };
      }
      const value = readPrimitive(cursor, type.slice(0, -2));
      if (!value.complete) return { argument: { type, value: values.map(String).join(", ") }, complete: false };
      values.push(value.value);
    }
    return { argument: { type, value: values.map(String).join(", ") }, complete: true };
  }
  const value = readPrimitive(cursor, type);
  return { argument: { type, value: value.value }, complete: value.complete };
};

const readNamedArgument = (cursor: AttributeCursor): PeClrCustomAttributeNamedArgument | null => {
  const kindByte = cursor.readU8();
  if (kindByte == null) return null;
  const kind = kindByte === 0x53 ? "field" : kindByte === 0x54 ? "property" : null;
  if (!kind) return null;
  const type = readFieldOrPropType(cursor);
  const name = cursor.readSerString();
  const value = type === "System.Type"
    ? cursor.readSerString()
    : readFixedArgument(cursor, type).argument.value;
  return { kind, name, type, value };
};

export const decodeCustomAttributeValue = (
  blob: Uint8Array | null,
  parameterTypes: Array<string | null>,
  context: string
): DecodedCustomAttributeValue => {
  const issues: string[] = [];
  if (!blob) return { fixedArguments: [], namedArguments: [], issues: [`${context} blob is absent.`] };
  const cursor = new AttributeCursor(blob, issues, context);
  // ECMA-335 II.23.3: every CustomAttrib blob starts with prolog 0x0001.
  const prolog = cursor.readU16();
  if (prolog !== 0x0001) issues.push(`${context} custom attribute prolog is not 0x0001.`);
  const fixedArguments: PeClrCustomAttributeArgument[] = [];
  let fixedArgumentsComplete = true;
  for (const type of parameterTypes) {
    const fixedArgument = readFixedArgument(cursor, type);
    fixedArguments.push(fixedArgument.argument);
    if (!fixedArgument.complete) {
      fixedArgumentsComplete = false;
      break;
    }
  }
  const namedArguments: PeClrCustomAttributeNamedArgument[] = [];
  if (!fixedArgumentsComplete) {
    issues.push(`${context} named arguments were not decoded because fixed arguments are incomplete.`);
  } else if (cursor.remaining >= 2) {
    const namedCount = cursor.readU16() ?? 0;
    for (let index = 0; index < namedCount; index += 1) {
      const argument = readNamedArgument(cursor);
      if (argument) namedArguments.push(argument);
    }
  } else if (cursor.remaining > 0) {
    issues.push(`${context} custom attribute blob has a trailing partial NumNamed field.`);
  }
  if (cursor.remaining > 0) {
    issues.push(`${context} custom attribute blob has ${cursor.remaining} trailing byte(s).`);
  }
  return issues.length
    ? { fixedArguments, namedArguments, issues }
    : { fixedArguments, namedArguments };
};
