"use strict";

import type { PeClrCustomAttributeArgument } from "./types.js";
import type { AttributeCursor } from "./metadata-attribute-cursor.js";
import { readFieldOrPropType, TYPE_ARRAY_SUFFIX, TYPE_ENUM_PREFIX, TYPE_OBJECT }
  from "./metadata-attribute-field-or-prop-type.js";
import { isPrimitiveAttributeType, readAttributePrimitive, type AttributeReadValue }
  from "./metadata-attribute-primitives.js";
import { runMetadataDecoding, type MetadataDecodingTask } from "./metadata-decoding-stack.js";

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
  // ECMA-335 II.23.3: an enum uses the declared underlying integer type, not a guessed width.
  const underlying = cursor.enumUnderlyingType(type.replace(/^enum /, ""));
  if (!underlying || !/^[iu][1248]$/.test(underlying)) {
    cursor.addIssue(`enum "${type}" underlying type is unresolved; decoding stopped.`);
    return { value: null, complete: false };
  }
  return readPrimitive(cursor, underlying);
};

function* readBoxedArgument(cursor: AttributeCursor): MetadataDecodingTask<AttributeReadValue> {
  const boxedType = readFieldOrPropType(cursor);
  if (!boxedType) return { value: null, complete: false };
  if (boxedType === TYPE_OBJECT) {
    // CustomAttributeDecoder.DecodeArgument unwraps TaggedObject once and requires a concrete type.
    cursor.addIssue("boxed object has no concrete serialized type; decoding stopped.");
    return { value: null, complete: false };
  }
  const boxedArgument = (yield readArgumentTask(cursor, boxedType)) as ReadFixedArgumentResult;
  return { value: boxedArgument.argument.value, complete: boxedArgument.complete };
}

function* readArrayArgument(cursor: AttributeCursor, type: string): MetadataDecodingTask<ReadFixedArgumentResult> {
  const count = cursor.readU32();
  // ECMA-335 II.23.3: CustomAttrib arrays encode null as 0xffffffff.
  if (count == null) return { argument: { type, value: null }, complete: false };
  if (count === 0xffffffff) return { argument: { type, value: null }, complete: true };
  if (count > 0x7fffffff) {
    cursor.addIssue("custom attribute array count is negative and is not the null sentinel.");
    return { argument: { type, value: null }, complete: false };
  }
  const values: Array<string | number | boolean | null> = [];
  const elementType = type.slice(0, -TYPE_ARRAY_SUFFIX.length);
  for (let index = 0; index < count; index += 1) {
    if (cursor.remaining <= 0) {
      cursor.addIssue(`array argument "${type}" is truncated after ${index}/${count} element(s).`);
      return { argument: { type, value: values.map(String).join(", ") }, complete: false };
    }
    const value = elementType === TYPE_OBJECT
      ? (yield readBoxedArgument(cursor)) as AttributeReadValue : readPrimitive(cursor, elementType);
    if (!value.complete) return { argument: { type, value: values.map(String).join(", ") }, complete: false };
    values.push(value.value);
  }
  return { argument: { type, value: values.map(String).join(", ") }, complete: true };
}

function* readArgumentTask(
  cursor: AttributeCursor,
  type: string | null
): MetadataDecodingTask<ReadFixedArgumentResult> {
  if (type?.endsWith(TYPE_ARRAY_SUFFIX)) return (yield readArrayArgument(cursor, type)) as ReadFixedArgumentResult;
  const value = type === TYPE_OBJECT
    ? (yield readBoxedArgument(cursor)) as AttributeReadValue : readPrimitive(cursor, type);
  return { argument: { type, value: value.value }, complete: value.complete };
}

export const readFixedArgument = (cursor: AttributeCursor, type: string | null): ReadFixedArgumentResult =>
  runMetadataDecoding(readArgumentTask(cursor, type));
