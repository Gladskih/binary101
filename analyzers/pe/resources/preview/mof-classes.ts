"use strict";

export interface BinaryMofClass {
  name: string | null;
  guid: string | null;
  namespace: string | null;
  superclass: string | null;
  properties: Array<{ name: string; type: string }>;
  methods: string[];
}

// bmfparse.c parse_root/parse_class_data/parse_class_property/parse_class_variable.
// https://github.com/pali/bmfdec/blob/master/bmfparse.c
const within = (offset: number, size: number, end: number): boolean =>
  offset >= 0 && size >= 0 && size <= end - offset;

const readString = (bytes: Uint8Array, offset: number, size: number, end: number):
  string | null => size % 2 === 0 && within(offset, size, end)
    ? new TextDecoder("utf-16le").decode(bytes.subarray(offset, offset + size)).split("\0", 1)[0] ?? ""
    : null;

const variableKinds = new Map<number, string>([
  [0x02, "SInt16"], [0x03, "SInt32"], [0x04, "Real32"], [0x05, "Real64"],
  [0x08, "String"], [0x0b, "Boolean"], [0x10, "SInt8"], [0x11, "UInt8"],
  [0x12, "UInt16"], [0x13, "UInt32"], [0x14, "SInt64"], [0x15, "UInt64"],
  [0x65, "Datetime"], [0x67, "Char16"], [0x0d, "Object"]
]);

const parseQualifiers = (
  bytes: Uint8Array, view: DataView, start: number, size: number,
  result: BinaryMofClass, issues: string[]
): void => {
  const end = start + size;
  const count = view.getUint32(start + 4, true);
  let cursor = start + 8;
  let parsedCount = 0;
  for (; parsedCount < count; parsedCount += 1) {
    if (!within(cursor, 16, end)) break;
    const length = view.getUint32(cursor, true);
    if (length < 16 || !within(cursor, length, end)) break;
    const nameSize = view.getUint32(cursor + 12, true);
    const name = readString(bytes, cursor + 16, nameSize, cursor + length);
    if (name === null) break;
    // bmfparse.c parse_qualifier: 0x08 is a UTF-16 string qualifier.
    if (name.toLowerCase() === "guid" && view.getUint32(cursor + 4, true) === 0x08) {
      result.guid = readString(bytes, cursor + 16 + nameSize,
        length - 16 - nameSize, cursor + length);
      if (result.guid === null) break;
    }
    cursor += length;
  }
  if (cursor !== end || parsedCount !== count) {
    issues.push("Binary MOF qualifier records are invalid or truncated.");
  }
};

const parseProperty = (
  bytes: Uint8Array, view: DataView, offset: number, size: number,
  result: BinaryMofClass, issues: string[]
): void => {
  const end = offset + size;
  if (view.getUint32(offset + 8, true) !== 0 ||
    view.getUint32(offset + 16, true) !== 0xffffffff) {
    issues.push("Binary MOF class property is invalid.");
    return;
  }
  const nameSize = view.getUint32(offset + 12, true);
  const name = readString(bytes, offset + 20, nameSize, end);
  const value = name === null ? null : readString(bytes, offset + 20 + nameSize,
    size - 20 - nameSize, end);
  if (name === null || value === null) {
    issues.push("Binary MOF class property string is invalid.");
    return;
  }
  if (view.getUint32(offset + 4, true) !== 0x08) return;
  if (name === "__CLASS") result.name = value;
  if (name === "__NAMESPACE") result.namespace = value;
  if (name === "__SUPERCLASS") result.superclass = value;
};

const parseVariable = (
  bytes: Uint8Array, view: DataView, offset: number, size: number,
  result: BinaryMofClass, issues: string[]
): void => {
  const type = view.getUint32(offset + 4, true);
  const length = view.getUint32(offset + 16, true);
  const declaredName = view.getUint32(offset + 12, true);
  const nameSize = declaredName === 0xffffffff ? length : declaredName;
  const name = readString(bytes, offset + 20, nameSize, offset + size);
  if (name === null || !within(offset + 20, length, offset + size)) {
    issues.push("Binary MOF variable name is invalid or truncated.");
    return;
  }
  const kind = variableKinds.get(type & 0xff) ?? `Type 0x${(type & 0xff).toString(16)}`;
  result.properties.push({ name, type: `${kind}${(type & 0x2000) ? "[]" : ""}` });
};

const parseVariables = (
  bytes: Uint8Array, view: DataView, start: number, end: number,
  result: BinaryMofClass, issues: string[]
): void => {
  if (!within(start, 8, end)) {
    issues.push("Binary MOF variable table is truncated.");
    return;
  }
  const size = view.getUint32(start, true);
  const count = view.getUint32(start + 4, true);
  if (size < 8 || !within(start, size, end)) {
    issues.push("Binary MOF variable table size is invalid.");
    return;
  }
  let cursor = start + 8;
  let parsedCount = 0;
  for (; parsedCount < count; parsedCount += 1) {
    if (!within(cursor, 4, start + size)) break;
    const recordSize = view.getUint32(cursor, true);
    if (recordSize < 20 || !within(cursor, recordSize, start + size)) break;
    if (view.getUint32(cursor + 16, true) === 0xffffffff) {
      parseProperty(bytes, view, cursor, recordSize, result, issues);
    } else parseVariable(bytes, view, cursor, recordSize, result, issues);
    cursor += recordSize;
  }
  if (cursor !== start + size || parsedCount !== count) {
    issues.push("Binary MOF variable records are invalid or truncated.");
  }
};

const parseMethods = (
  bytes: Uint8Array, view: DataView, start: number, end: number,
  result: BinaryMofClass, issues: string[]
): void => {
  if (!within(start, 8, end)) {
    issues.push("Binary MOF method table is truncated.");
    return;
  }
  const size = view.getUint32(start, true);
  const count = view.getUint32(start + 4, true);
  if (size < 8 || !within(start, size, end)) {
    issues.push("Binary MOF method table size is invalid.");
    return;
  }
  let cursor = start + 8;
  let parsedCount = 0;
  for (; parsedCount < count; parsedCount += 1) {
    if (!within(cursor, 20, start + size)) break;
    const recordSize = view.getUint32(cursor, true);
    const declaredSize = view.getUint32(cursor + 12, true);
    const nameSize = declaredSize === 0xffffffff ?
      view.getUint32(cursor + 16, true) : declaredSize;
    if (recordSize < 20 || !within(cursor, recordSize, start + size)) break;
    const name = readString(bytes, cursor + 20, nameSize, cursor + recordSize);
    if (name === null) break;
    result.methods.push(name);
    cursor += recordSize;
  }
  if (cursor !== start + size || parsedCount !== count) {
    issues.push("Binary MOF method records are invalid or truncated.");
  }
};

const parseClass = (
  bytes: Uint8Array, view: DataView, start: number, size: number, issues: string[]
): BinaryMofClass | null => {
  const result: BinaryMofClass = { name: null, guid: null, namespace: null, superclass: null,
    properties: [], methods: [] };
  if (view.getUint32(start + 4, true) !== 0) {
    issues.push("Binary MOF class header is invalid.");
    return null;
  }
  const qualifierSize = view.getUint32(start + 8, true);
  const dataSize = view.getUint32(start + 12, true);
  if (view.getUint32(start + 16, true) === 1) {
    issues.push("Binary MOF class instance records are not supported.");
    return null;
  }
  if (view.getUint32(start + 16, true) !== 0 || qualifierSize < 8 ||
    qualifierSize > dataSize || !within(start + 20, dataSize, start + size)) {
    issues.push("Binary MOF class data is unsupported or truncated.");
    return null;
  }
  // The first class-data block contains qualifiers; the next contains variables.
  if (view.getUint32(start + 20, true) !== qualifierSize) {
    issues.push("Binary MOF qualifier table size is inconsistent.");
    return null;
  }
  parseQualifiers(bytes, view, start + 20, qualifierSize, result, issues);
  parseVariables(bytes, view, start + 20 + qualifierSize, start + 20 + dataSize,
    result, issues);
  parseMethods(bytes, view, start + 20 + dataSize, start + size, result, issues);
  return result;
};

export const parseBinaryMofClasses = (
  bytes: Uint8Array, firstPartEnd: number, issues: string[]
): BinaryMofClass[] => {
  if (!Number.isSafeInteger(firstPartEnd) || !within(8, 12, firstPartEnd) ||
    firstPartEnd > bytes.length) {
    issues.push("Binary MOF class root is truncated.");
    return [];
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  if (view.getUint32(8, true) !== 1 || view.getUint32(12, true) !== 1) {
    issues.push("Binary MOF class root version is unsupported.");
    return [];
  }
  const count = view.getUint32(16, true);
  const classes: BinaryMofClass[] = [];
  let cursor = 20;
  let parsedCount = 0;
  for (; parsedCount < count; parsedCount += 1) {
    if (!within(cursor, 4, firstPartEnd)) break;
    const size = view.getUint32(cursor, true);
    if (size < 20 || !within(cursor, size, firstPartEnd)) break;
    const parsed = parseClass(bytes, view, cursor, size, issues);
    if (parsed) classes.push(parsed);
    cursor += size;
  }
  if (cursor !== firstPartEnd || parsedCount !== count) {
    issues.push("Binary MOF class records are invalid or truncated.");
  }
  return classes;
};
