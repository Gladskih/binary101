"use strict";

import type {
  PeClrCustomAttributeArgument,
  PeClrCustomAttributeNamedArgument
} from "./types.js";
import {
  AttributeCursor,
  BYTE_WIDTH_U8,
  BYTE_WIDTH_U16,
  BYTE_WIDTH_U32,
  BYTE_WIDTH_U64,
  NAMED_ARGUMENT_FIELD_TAG,
  NAMED_ARGUMENT_PROPERTY_TAG
} from "./metadata-attribute-cursor.js";
import {
  readFieldOrPropType,
  TYPE_ARRAY_SUFFIX,
  TYPE_BOOL,
  TYPE_CHAR,
  TYPE_ENUM_PREFIX,
  TYPE_I1,
  TYPE_I2,
  TYPE_I4,
  TYPE_I8,
  TYPE_OBJECT,
  TYPE_R4,
  TYPE_R8,
  TYPE_STRING,
  TYPE_SYSTEM_TYPE,
  TYPE_U1,
  TYPE_U2,
  TYPE_U4,
  TYPE_U8
} from "./metadata-attribute-field-or-prop-type.js";

// ECMA-335 II.23.3 defines the serialized CustomAttrib blob and named argument tags.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
const TYPE_NAME_SEPARATOR = " ";
const TYPE_METADATA_TOKEN_MARKER = "#";
const PREFERRED_ENUM_VALUE_BYTE_WIDTHS = [
  BYTE_WIDTH_U32,
  BYTE_WIDTH_U64,
  BYTE_WIDTH_U16,
  BYTE_WIDTH_U8
] as const;

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

const readIntegralValue = (cursor: AttributeCursor, byteLength: number): string | number | null => {
  if (byteLength === BYTE_WIDTH_U8) return cursor.readU8();
  if (byteLength === BYTE_WIDTH_U16) return cursor.readU16();
  if (byteLength === BYTE_WIDTH_U32) return cursor.readU32();
  const low = cursor.readU32();
  const high = cursor.readU32();
  return low == null || high == null
    ? null
    : `0x${high.toString(16).padStart(8, "0")}${low.toString(16).padStart(8, "0")}`;
};

const PRIMITIVE_ARGUMENT_TYPES = new Set([
  TYPE_BOOL,
  TYPE_CHAR,
  TYPE_I1,
  TYPE_U1,
  TYPE_I2,
  TYPE_U2,
  TYPE_I4,
  TYPE_U4,
  TYPE_I8,
  TYPE_U8,
  TYPE_R4,
  TYPE_R8,
  TYPE_STRING,
  TYPE_SYSTEM_TYPE,
  TYPE_OBJECT
]);

const isEnumLikeArgumentType = (type: string | null): boolean =>
  !!type &&
  (type.startsWith(TYPE_ENUM_PREFIX) ||
    (!PRIMITIVE_ARGUMENT_TYPES.has(type) &&
      !type.includes(TYPE_NAME_SEPARATOR) &&
      !type.includes(TYPE_METADATA_TOKEN_MARKER)));

const readWithIssueStatus = (
  cursor: AttributeCursor,
  readValue: () => string | number | boolean | null
): ReadValueResult => {
  const issueCount = cursor.issueCount;
  return { value: readValue(), complete: cursor.issueCount === issueCount };
};

const readPrimitive = (cursor: AttributeCursor, type: string | null): ReadValueResult => {
  if (type === TYPE_STRING || type === TYPE_SYSTEM_TYPE) {
    return readWithIssueStatus(cursor, () => cursor.readSerString());
  }
  if (type === TYPE_BOOL) return readWithIssueStatus(cursor, () => (cursor.readU8() ?? 0) !== 0);
  if (type === TYPE_CHAR) {
    return readWithIssueStatus(cursor, () => {
      const value = cursor.readU16();
      return value == null ? null : String.fromCharCode(value);
    });
  }
  if (type === TYPE_I1 || type === TYPE_U1) return readWithIssueStatus(cursor, () => cursor.readU8());
  if (type === TYPE_I2 || type === TYPE_U2) return readWithIssueStatus(cursor, () => cursor.readU16());
  if (type === TYPE_I4 || type === TYPE_U4) return readWithIssueStatus(cursor, () => cursor.readU32());
  if (type === TYPE_I8 || type === TYPE_U8) {
    return readWithIssueStatus(cursor, () => readIntegralValue(cursor, BYTE_WIDTH_U64));
  }
  if (type === TYPE_R4) return readWithIssueStatus(cursor, () => cursor.readF32());
  if (type === TYPE_R8) return readWithIssueStatus(cursor, () => cursor.readF64());
  if (type?.startsWith(TYPE_ENUM_PREFIX)) return readWithIssueStatus(cursor, () => cursor.readU32());
  if (type && !type.includes(TYPE_NAME_SEPARATOR) && !type.includes(TYPE_METADATA_TOKEN_MARKER)) {
    return readWithIssueStatus(cursor, () => cursor.readU32());
  }
  cursor.addIssue(`fixed argument type "${type ?? "unknown"}" is not supported; decoding stopped.`);
  return { value: null, complete: false };
};

const readFixedBoxedArgument = (
  cursor: AttributeCursor,
  remainingFixedArgumentCount: number
): ReadValueResult => {
  const boxedType = readFieldOrPropType(cursor);
  if (!boxedType) return { value: null, complete: false };
  const boxedArgument = readFixedArgument(cursor, boxedType, remainingFixedArgumentCount);
  return { value: boxedArgument.argument.value, complete: boxedArgument.complete };
};

const readFixedArgument = (
  cursor: AttributeCursor,
  type: string | null,
  remainingFixedArgumentCount = 1
): ReadFixedArgumentResult => {
  if (type?.endsWith(TYPE_ARRAY_SUFFIX)) {
    const count = cursor.readU32();
    // ECMA-335 II.23.3: a CustomAttrib array count of 0xffffffff encodes null.
    if (count == null || count === 0xffffffff) {
      return { argument: { type, value: null }, complete: true };
    }
    const values: Array<string | number | boolean | null> = [];
    for (let index = 0; index < count; index += 1) {
      if (cursor.remaining <= 0) {
        cursor.addIssue(`array argument "${type}" is truncated after ${index}/${count} element(s).`);
        return { argument: { type, value: values.map(String).join(", ") }, complete: false };
      }
      const value = readPrimitive(cursor, type.slice(0, -TYPE_ARRAY_SUFFIX.length));
      if (!value.complete) return { argument: { type, value: values.map(String).join(", ") }, complete: false };
      values.push(value.value);
    }
    return { argument: { type, value: values.map(String).join(", ") }, complete: true };
  }
  if (type === TYPE_OBJECT) {
    const value = readFixedBoxedArgument(cursor, remainingFixedArgumentCount);
    return { argument: { type, value: value.value }, complete: value.complete };
  }
  if (isEnumLikeArgumentType(type) && remainingFixedArgumentCount === 0) {
    const byteLength = PREFERRED_ENUM_VALUE_BYTE_WIDTHS.find(candidate =>
      cursor.hasTrailingNamedCountAfter(candidate)
    ) ?? 4;
    const value = readWithIssueStatus(cursor, () => readIntegralValue(cursor, byteLength));
    return { argument: { type, value: value.value }, complete: value.complete };
  }
  const value = readPrimitive(cursor, type);
  return { argument: { type, value: value.value }, complete: value.complete };
};

const readNamedEnumValue = (
  cursor: AttributeCursor,
  remainingNamedArgumentCount: number
): ReadValueResult => {
  // ECMA-335 II.23.3 stores enum values as their underlying integer type, while
  // FieldOrPropType carries only the enum type name. Infer the encoded width from
  // the next named-argument boundary when metadata resolution is not available here.
  const byteLength = PREFERRED_ENUM_VALUE_BYTE_WIDTHS.find(candidate =>
    cursor.hasEnumValueBoundary(candidate, remainingNamedArgumentCount)
  ) ?? 4;
  return readWithIssueStatus(cursor, () => readIntegralValue(cursor, byteLength));
};

const readNamedArgumentValue = (
  cursor: AttributeCursor,
  type: string | null,
  remainingNamedArgumentCount: number
): ReadValueResult => {
  if (type === TYPE_SYSTEM_TYPE) return readWithIssueStatus(cursor, () => cursor.readSerString());
  if (type?.startsWith(TYPE_ENUM_PREFIX)) return readNamedEnumValue(cursor, remainingNamedArgumentCount);
  if (type === TYPE_OBJECT) {
    const boxedType = readFieldOrPropType(cursor);
    if (!boxedType) return { value: null, complete: false };
    if (boxedType.startsWith(TYPE_ENUM_PREFIX)) {
      return readNamedEnumValue(cursor, remainingNamedArgumentCount);
    }
    const boxedArgument = readFixedArgument(cursor, boxedType);
    return { value: boxedArgument.argument.value, complete: boxedArgument.complete };
  }
  const value = readFixedArgument(cursor, type);
  return { value: value.argument.value, complete: value.complete };
};

const readNamedArgument = (
  cursor: AttributeCursor,
  remainingNamedArgumentCount: number
): PeClrCustomAttributeNamedArgument | null => {
  const kindByte = cursor.readU8();
  if (kindByte == null) return null;
  const kind = kindByte === NAMED_ARGUMENT_FIELD_TAG
    ? "field"
    : kindByte === NAMED_ARGUMENT_PROPERTY_TAG
      ? "property"
      : null;
  if (!kind) {
    cursor.addIssue(
      `named argument kind 0x${kindByte.toString(16).padStart(2, "0")} is not FIELD or PROPERTY.`
    );
    return null;
  }
  const type = readFieldOrPropType(cursor);
  const name = cursor.readSerString();
  const value = readNamedArgumentValue(cursor, type, remainingNamedArgumentCount);
  return value.complete ? { kind, name, type, value: value.value } : null;
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
  if (prolog !== 0x0001) {
    issues.push(`${context} custom attribute prolog is not 0x0001.`);
  }
  const fixedArguments: PeClrCustomAttributeArgument[] = [];
  let fixedArgumentsComplete = true;
  for (const type of parameterTypes) {
    const fixedArgument = readFixedArgument(
      cursor,
      type,
      parameterTypes.length - fixedArguments.length - 1
    );
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
      const argument = readNamedArgument(cursor, namedCount - index - 1);
      if (!argument) {
        issues.push(
          `${context} named argument ${index + 1}/${namedCount} could not be decoded; decoding stopped.`
        );
        break;
      }
      namedArguments.push(argument);
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
