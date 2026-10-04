"use strict";

import type { PeClrCustomAttributeNamedArgument } from "./types.js";
import type { PeClrPermissionSet } from "./metadata-value-types.js";
import { MetadataBlobCursor } from "./metadata-blob-cursor.js";
import { AttributeCursor } from "./metadata-attribute-cursor.js";
import { readNamedArgument } from "./metadata-attributes.js";
import { decodeMetadataUtf16 } from "./metadata-utf16.js";

const readSecurityArguments = (
  bytes: Uint8Array,
  context: string,
  enumTypes: ReadonlyMap<string, string>
): { namedArguments: PeClrCustomAttributeNamedArgument[]; issues?: string[] } => {
  const issues: string[] = [];
  const blob = new MetadataBlobCursor(bytes, issues, context);
  const count = blob.readCompressedUInt();
  const cursor = new AttributeCursor(blob.readBytes(blob.remaining) ?? new Uint8Array(), issues, context, enumTypes);
  const namedArguments: PeClrCustomAttributeNamedArgument[] = [];
  for (let index = 0; index < (count ?? 0); index += 1) {
    const argument = readNamedArgument(cursor);
    if (!argument) break;
    namedArguments.push(argument);
  }
  if (count != null && count !== namedArguments.length) issues.push(`${context}: named argument count is incomplete.`);
  if (cursor.remaining) issues.push(`${context}: named arguments have ${cursor.remaining} trailing byte(s).`);
  return { namedArguments, ...(issues.length ? { issues } : {}) };
};

export const parsePermissionSet = (
  bytes: Uint8Array,
  context: string,
  enumTypes: ReadonlyMap<string, string> = new Map()
): PeClrPermissionSet => {
  const issues: string[] = [];
  // ECMA-335 II.22.11: legacy permission sets are UTF-16 XML; binary sets start with '.'.
  // Runtime binary entries also carry a compressed byte length and compressed NumNamed:
  // https://github.com/0xd4d/dnlib/blob/master/src/DotNet/DeclSecurityReader.cs
  if (bytes[0] !== 0x2e) {
    if (!bytes.length) issues.push(`${context}: permission set is empty.`);
    return { kind: "security", encoding: "xml", xml: decodeMetadataUtf16(bytes, issues, context),
      ...(issues.length ? { issues } : {}) };
  }
  return readBinaryPermissionSet(bytes, issues, context, enumTypes);
};

const readSecurityAttribute = (
  cursor: MetadataBlobCursor,
  enumTypes: ReadonlyMap<string, string>
) => {
  const typeName = cursor.readUtf8();
  if (typeName == null) return null;
  const size = cursor.readCompressedUInt();
  if (size == null) return null;
  const payload = cursor.readBytes(size);
  return payload ? { typeName, ...readSecurityArguments(payload, `${cursor.context} ${typeName}`, enumTypes) } : null;
};

const readBinaryPermissionSet = (
  bytes: Uint8Array,
  issues: string[],
  context: string,
  enumTypes: ReadonlyMap<string, string>
): PeClrPermissionSet => {
  const cursor = new MetadataBlobCursor(bytes.subarray(1), issues, context);
  const count = cursor.readCompressedUInt();
  const attributes: Extract<PeClrPermissionSet, { encoding: "binary" }>["attributes"] = [];
  for (let index = 0; index < (count ?? 0); index += 1) {
    const attribute = readSecurityAttribute(cursor, enumTypes);
    if (!attribute) break;
    attributes.push(attribute);
  }
  if (count != null && attributes.length !== count) issues.push(`${context}: security attribute count is incomplete.`);
  cursor.finish();
  return { kind: "security", encoding: "binary", attributes, ...(issues.length ? { issues } : {}) };
};
