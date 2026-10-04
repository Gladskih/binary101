"use strict";

import type {
  PeClrCustomAttributeArgument,
  PeClrCustomAttributeNamedArgument
} from "./types.js";
import {
  AttributeCursor,
  NAMED_ARGUMENT_FIELD_TAG,
  NAMED_ARGUMENT_PROPERTY_TAG
} from "./metadata-attribute-cursor.js";
import { readFieldOrPropType, TYPE_ARRAY_SUFFIX, TYPE_ENUM_PREFIX, TYPE_OBJECT }
  from "./metadata-attribute-field-or-prop-type.js";
import { isPrimitiveAttributeType, readAttributePrimitive, type AttributeReadValue }
  from "./metadata-attribute-primitives.js";

// ECMA-335 II.23.3 defines the serialized CustomAttrib blob and named argument tags.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
interface DecodedCustomAttributeValue {
  fixedArguments: PeClrCustomAttributeArgument[];
  namedArguments: PeClrCustomAttributeNamedArgument[];
  issues?: string[];
}

interface ReadFixedArgumentResult {
  argument: PeClrCustomAttributeArgument;
  complete: boolean;
}

const isEnumLikeArgumentType = (type: string | null): boolean =>
  !!type && (type.startsWith(TYPE_ENUM_PREFIX) ||
    (!isPrimitiveAttributeType(type) && !type.includes(" ") && !type.includes("#")));

const readPrimitive = (cursor: AttributeCursor, type: string | null): AttributeReadValue => {
  const primitive = readAttributePrimitive(cursor, type);
  if (primitive) return primitive;
  if (isEnumLikeArgumentType(type)) return readEnumValue(cursor, type!);
  cursor.addIssue(`fixed argument type "${type ?? "unknown"}" is not supported; decoding stopped.`);
  return { value: null, complete: false };
};
const readEnumValue = (cursor: AttributeCursor, type: string): AttributeReadValue => {
  // ECMA-335 II.23.3: an enum value uses its declared underlying integer type.
  const underlying = cursor.enumUnderlyingType(type.replace(/^enum /, ""));
  if (!underlying || !/^[iu][1248]$/.test(underlying)) {
    cursor.addIssue(`enum "${type}" underlying type is unresolved; decoding stopped.`);
    return { value: null, complete: false };
  }
  return readPrimitive(cursor, underlying);
};

const readFixedBoxedArgument = (
  cursor: AttributeCursor
): AttributeReadValue => {
  const boxedType = readFieldOrPropType(cursor);
  if (!boxedType) return { value: null, complete: false };
  if (boxedType === TYPE_OBJECT) {
    // CustomAttributeDecoder.DecodeArgument unwraps TaggedObject once; another OBJECT is invalid.
    cursor.addIssue("boxed object has no concrete serialized type; decoding stopped.");
    return { value: null, complete: false };
  }
  const boxedArgument = readFixedArgument(cursor, boxedType);
  return { value: boxedArgument.argument.value, complete: boxedArgument.complete };
};

const readFixedArgument = (
  cursor: AttributeCursor,
  type: string | null
): ReadFixedArgumentResult => {
  if (!cursor.enterValue()) return { argument: { type, value: null }, complete: false };
  try {
    return readFixedArgumentCore(cursor, type);
  } finally {
    cursor.leaveValue();
  }
};

const readFixedArgumentCore = (
  cursor: AttributeCursor,
  type: string | null
): ReadFixedArgumentResult => {
  if (type?.endsWith(TYPE_ARRAY_SUFFIX)) return readArrayArgument(cursor, type);
  if (type === TYPE_OBJECT) {
    const value = readFixedBoxedArgument(cursor);
    return { argument: { type, value: value.value }, complete: value.complete };
  }
  const value = readPrimitive(cursor, type);
  return { argument: { type, value: value.value }, complete: value.complete };
};

const readArrayArgument = (cursor: AttributeCursor, type: string): ReadFixedArgumentResult => {
  const count = cursor.readU32();
  // ECMA-335 II.23.3: a CustomAttrib array count of 0xffffffff encodes null.
  if (count == null) return { argument: { type, value: null }, complete: false };
  if (count === 0xffffffff) return { argument: { type, value: null }, complete: true };
  const values: Array<string | number | boolean | null> = [];
  const elementType = type.slice(0, -TYPE_ARRAY_SUFFIX.length);
  for (let index = 0; index < count; index += 1) {
    if (cursor.remaining <= 0) {
      cursor.addIssue(`array argument "${type}" is truncated after ${index}/${count} element(s).`);
      return { argument: { type, value: values.map(String).join(", ") }, complete: false };
    }
    const value = elementType === TYPE_OBJECT
      ? readFixedBoxedArgument(cursor)
      : readPrimitive(cursor, elementType);
    if (!value.complete) return { argument: { type, value: values.map(String).join(", ") }, complete: false };
    values.push(value.value);
  }
  return { argument: { type, value: values.map(String).join(", ") }, complete: true };
};

const readNamedArgument = (
  cursor: AttributeCursor
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
  const value = readFixedArgument(cursor, type);
  return value.complete ? { kind, name, type, value: value.argument.value } : null;
};

export const decodeCustomAttributeValue = (
  blob: Uint8Array | null,
  parameterTypes: Array<string | null>,
  context: string,
  enumTypes: ReadonlyMap<string, string> = new Map()
): DecodedCustomAttributeValue => {
  const issues: string[] = [];
  if (!blob) return { fixedArguments: [], namedArguments: [], issues: [`${context} blob is absent.`] };
  const cursor = new AttributeCursor(blob, issues, context, enumTypes);
  // ECMA-335 II.23.3: every CustomAttrib blob starts with prolog 0x0001.
  const prolog = cursor.readU16();
  if (prolog !== 0x0001) {
    issues.push(`${context} custom attribute prolog is not 0x0001.`);
    return { fixedArguments: [], namedArguments: [], issues };
  }
  const fixed = readFixedArguments(cursor, parameterTypes);
  const namedArguments = fixed.complete ? readNamedArguments(cursor) : [];
  if (!fixed.complete) cursor.addIssue("named arguments were not decoded because fixed arguments are incomplete.");
  if (cursor.remaining > 0) cursor.addIssue(`custom attribute blob has ${cursor.remaining} trailing byte(s).`);
  return { fixedArguments: fixed.arguments, namedArguments, ...(issues.length ? { issues } : {}) };
};

const readFixedArguments = (
  cursor: AttributeCursor,
  parameterTypes: Array<string | null>
): { arguments: PeClrCustomAttributeArgument[]; complete: boolean } => {
  const argumentsList: PeClrCustomAttributeArgument[] = [];
  for (const type of parameterTypes) {
    const fixedArgument = readFixedArgument(cursor, type);
    argumentsList.push(fixedArgument.argument);
    if (!fixedArgument.complete) return { arguments: argumentsList, complete: false };
  }
  return { arguments: argumentsList, complete: true };
};

const readNamedArguments = (cursor: AttributeCursor): PeClrCustomAttributeNamedArgument[] => {
  const namedArguments: PeClrCustomAttributeNamedArgument[] = [];
  if (cursor.remaining >= 2) {
    const namedCount = cursor.readU16() ?? 0;
    for (let index = 0; index < namedCount; index += 1) {
      const argument = readNamedArgument(cursor);
      if (!argument) {
        cursor.addIssue(
          `named argument ${index + 1}/${namedCount} could not be decoded; decoding stopped.`
        );
        break;
      }
      namedArguments.push(argument);
    }
  } else if (cursor.remaining > 0) {
    cursor.addIssue("custom attribute blob has a trailing partial NumNamed field.");
  } else {
    cursor.addIssue("custom attribute blob is missing NumNamed.");
  }
  return namedArguments;
};
