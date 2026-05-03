"use strict";

import { decodeDotNetResourceValue } from "./dotnet-resource-values.js";
import type { PeClrManagedResourceValue } from "./managed-resource-types.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });
const utf16Decoder = new TextDecoder("utf-16le", { fatal: false });

type ResourceValueTable = {
  count: number;
  dataSectionOffset: number;
  namesOffset: number;
  namePositionsOffset: number;
  userTypes: string[];
  version: number;
};

const readSevenBitEncodedInt = (
  bytes: Uint8Array,
  offset: number
): { value: number; next: number } | null => {
  let result = 0;
  // ResourceReader uses BinaryReader 7-bit encoded integers for resource names and strings:
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
  for (let shift = 0; shift < 35; shift += 7) {
    const byte = bytes[offset + shift / 7];
    if (byte == null) return null;
    result += (byte & 0x7f) * 2 ** shift;
    if (result > 0xffffffff) return null;
    if ((byte & 0x80) === 0) {
      return {
        value: result > 0x7fffffff ? result - 0x100000000 : result,
        next: offset + shift / 7 + 1
      };
    }
  }
  return null;
};

const readBinaryString = (
  bytes: Uint8Array,
  offset: number
): { value: string; next: number } | null => {
  const length = readSevenBitEncodedInt(bytes, offset);
  if (!length || length.value < 0 || length.next + length.value > bytes.length) return null;
  return {
    value: utf8Decoder.decode(bytes.subarray(length.next, length.next + length.value)),
    next: length.next + length.value
  };
};

const readUtf16Name = (
  bytes: Uint8Array,
  offset: number
): { value: string; dataOffsetPosition: number } | null => {
  const length = readSevenBitEncodedInt(bytes, offset);
  if (!length || length.value < 0 || length.next + length.value + 4 > bytes.length) return null;
  return {
    value: utf16Decoder.decode(bytes.subarray(length.next, length.next + length.value)),
    dataOffsetPosition: length.next + length.value
  };
};

export const parseDotNetResources = async (
  payload: Uint8Array,
  issues: string[]
): Promise<PeClrManagedResourceValue[] | null> => {
  if (payload.length < 4) return null;
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  // System.Resources .resources files start with ResourceManager.MagicNumber 0xBEEFCACE:
  // https://learn.microsoft.com/en-us/dotnet/api/system.resources.resourcemanager.magicnumber
  if (view.getUint32(0, true) !== 0xbeefcace) return null;
  if (payload.length < 12) {
    issues.push(".resources ResourceManager header is truncated.");
    return [];
  }
  const offset = readResourceSetHeader(payload, view, issues);
  return offset == null ? [] : parseResourceSet(payload, view, offset, issues);
};

const readResourceSetHeader = (
  payload: Uint8Array,
  view: DataView,
  issues: string[]
): number | null => {
  const resourceManagerHeaderSize = view.getInt32(8, true);
  if (resourceManagerHeaderSize < 0 || 12 + resourceManagerHeaderSize > payload.length) {
    issues.push(".resources ResourceManager header extends past payload.");
    return null;
  }
  const offset = 12 + resourceManagerHeaderSize;
  if (offset + 12 <= payload.length) return offset;
  issues.push(".resources RuntimeResourceSet header extends past payload.");
  return null;
};

const parseResourceSet = async (
  payload: Uint8Array,
  view: DataView,
  offset: number,
  issues: string[]
): Promise<PeClrManagedResourceValue[]> => {
  const version = view.getUint32(offset, true);
  const count = view.getInt32(offset + 4, true);
  const typeCount = view.getInt32(offset + 8, true);
  if (version !== 1 && version !== 2) issues.push(`Unsupported .resources version ${version}.`);
  if (count < 0 || typeCount < 0 || count > 10000 || typeCount > 10000) {
    issues.push(".resources declares an unreasonable entry or type count.");
    return [];
  }
  return parseResourceEntries(payload, view, offset + 12, version, count, typeCount, issues);
};

const parseResourceEntries = async (
  payload: Uint8Array,
  view: DataView,
  offset: number,
  version: number,
  count: number,
  typeCount: number,
  issues: string[]
): Promise<PeClrManagedResourceValue[]> => {
  const typeTable = readUserTypeTable(payload, offset, typeCount, issues);
  if (!typeTable) return [];
  return parseNamedResourceValues(payload, view, (typeTable.next + 7) & ~7, {
    count,
    dataSectionOffset: 0,
    namesOffset: 0,
    namePositionsOffset: 0,
    userTypes: typeTable.userTypes,
    version
  }, issues);
};

const readUserTypeTable = (
  payload: Uint8Array,
  offset: number,
  typeCount: number,
  issues: string[]
): { userTypes: string[]; next: number } | null => {
  const userTypes: string[] = [];
  let next = offset;
  for (let index = 0; index < typeCount; index += 1) {
    const type = readBinaryString(payload, next);
    if (!type) {
      issues.push(".resources type-name table is truncated.");
      return null;
    }
    userTypes.push(type.value);
    next = type.next;
  }
  return { userTypes, next };
};

const parseNamedResourceValues = async (
  payload: Uint8Array,
  view: DataView,
  offset: number,
  table: ResourceValueTable,
  issues: string[]
): Promise<PeClrManagedResourceValue[]> => {
  const namePositionsOffset = offset + table.count * 4;
  const dataSectionOffsetPosition = namePositionsOffset + table.count * 4;
  if (dataSectionOffsetPosition + 4 > payload.length) {
    issues.push(".resources hash/name-position tables are truncated.");
    return [];
  }
  const dataSectionOffset = view.getUint32(dataSectionOffsetPosition, true);
  if (dataSectionOffset > payload.length) {
    issues.push(".resources data section offset is outside the payload.");
    return [];
  }
  return readResourceValues(payload, view, {
    ...table,
    dataSectionOffset,
    namesOffset: dataSectionOffsetPosition + 4,
    namePositionsOffset
  }, issues);
};

const readResourceValues = async (
  payload: Uint8Array,
  view: DataView,
  table: ResourceValueTable,
  issues: string[]
): Promise<PeClrManagedResourceValue[]> => {
  const values: PeClrManagedResourceValue[] = [];
  for (let index = 0; index < table.count; index += 1) {
    const namePosition = view.getUint32(table.namePositionsOffset + index * 4, true);
    const name = readUtf16Name(payload, table.namesOffset + namePosition);
    if (!name) {
      issues.push(`.resources name ${index + 1} is truncated.`);
      continue;
    }
    values.push(await readResourceValue(payload, view, table, name));
  }
  return values;
};

const readResourceValue = async (
  payload: Uint8Array,
  view: DataView,
  table: ResourceValueTable,
  name: { value: string; dataOffsetPosition: number }
): Promise<PeClrManagedResourceValue> => {
  const dataOffset = view.getUint32(name.dataOffsetPosition, true);
  const type = readSevenBitEncodedInt(payload, table.dataSectionOffset + dataOffset);
  if (!type) {
    return { name: name.value, type: "Unknown", value: null, opaque: true, issues: ["Resource value type code is truncated."] };
  }
  return decodeDotNetResourceValue(
    payload,
    type,
    name.value,
    table.version,
    table.userTypes,
    readSevenBitEncodedInt
  );
};
