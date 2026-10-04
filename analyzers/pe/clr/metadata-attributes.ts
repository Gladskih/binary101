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
import { readFieldOrPropType }
  from "./metadata-attribute-field-or-prop-type.js";
import { readFixedArgument } from "./metadata-attribute-values.js";

// ECMA-335 II.23.3 defines the serialized CustomAttrib blob and named argument tags.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
interface DecodedCustomAttributeValue {
  fixedArguments: PeClrCustomAttributeArgument[];
  namedArguments: PeClrCustomAttributeNamedArgument[];
  issues?: string[];
}

export const readNamedArgument = (
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
