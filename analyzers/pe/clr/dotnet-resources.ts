"use strict";

import { decodeDotNetResourceValue } from "./dotnet-resource-values.js";
import type { PeClrManagedResourceValue } from "./managed-resource-types.js";

import { readSevenBitEncodedInt, readBinaryString, readUtf16Name } from "./dotnet-resource-encoding.js";

type ResourceValueTable = {
  count: number;
  dataSectionOffset: number;
  namesOffset: number;
  namePositionsOffset: number;
  userTypes: string[];
  version: number;
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
  if (view.getInt32(4, true) < 0) {
    issues.push(".resources ResourceManager header version is invalid.");
    return null;
  }
  if (resourceManagerHeaderSize < 0 || resourceManagerHeaderSize > payload.length - 12) {
    issues.push(".resources ResourceManager header extends past payload.");
    return null;
  }
  let offset = 12 + resourceManagerHeaderSize;
  if (view.getInt32(4, true) <= 1) {
    const next = readReaderTypes(payload, offset, issues);
    if (next == null) return null;
    offset = next;
  }
  if (offset + 12 <= payload.length) return offset;
  issues.push(".resources RuntimeResourceSet header extends past payload.");
  return null;
};

const readReaderTypes = (payload: Uint8Array, declaredEnd: number, issues: string[]): number | null => {
  const reader = readBinaryString(payload, 12);
  const resourceSet = reader && readBinaryString(payload, reader.next);
  if (!reader || !resourceSet) {
    issues.push(".resources ResourceReader/ResourceSet type names are truncated.");
    return null;
  }
  if (!["System.Resources.ResourceReader", "System.Resources.Extensions.DeserializingResourceReader"]
    .includes(reader.value.split(",", 1)[0]!.trim())) {
    issues.push(`Unsupported .resources ResourceReader ${JSON.stringify(reader.value)}.`);
    return null;
  }
  // ResourceReader ignores the declared skip count for v1 and consumes the two strings.
  if (resourceSet.next !== declaredEnd) issues.push(".resources ResourceManager header size is inconsistent.");
  return resourceSet.next;
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
  if (version !== 1 && version !== 2) {
    issues.push(`Unsupported .resources version ${version}.`);
    return [];
  }
  // Local analysis policy: keep corrupt resource counts from allocating unbounded tables.
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
  if (dataSectionOffset < dataSectionOffsetPosition + 4 || dataSectionOffset > payload.length) {
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
  // ResourceReader.GetResourceData sorts data offsets to bound each serialized value.
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
  const names = readResourceNames(payload, view, table, issues);
  const starts = [...new Set(names.map(name => name.dataOffset))].sort((left, right) => left - right);
  const ends = new Map(starts.map((start, index) => [start, starts[index + 1] ?? payload.length]));
  const decoded = new Map<number, PeClrManagedResourceValue>();
  const values: PeClrManagedResourceValue[] = [];
  for (const name of names) {
    let value = decoded.get(name.dataOffset);
    if (!value) {
      value = await readResourceValue(payload.subarray(0, ends.get(name.dataOffset)), table, name);
      decoded.set(name.dataOffset, value);
    }
    values.push({ ...value, name: name.value });
  }
  return values;
};

const readResourceNames = (
  payload: Uint8Array,
  view: DataView,
  table: ResourceValueTable,
  issues: string[]
): Array<{ value: string; dataOffset: number }> => {
  const names: Array<{ value: string; dataOffset: number }> = [];
  const seen = new Set<string>();
  for (let index = 0; index < table.count; index += 1) {
    const namePosition = view.getInt32(table.namePositionsOffset + index * 4, true);
    const name = namePosition < 0 ? null :
      readUtf16Name(payload, table.namesOffset + namePosition, table.dataSectionOffset);
    if (!name) {
      issues.push(`.resources name ${index + 1} is truncated.`);
      continue;
    }
    const dataOffset = view.getInt32(name.dataOffsetPosition, true);
    if (dataOffset < 0 || dataOffset >= payload.length - table.dataSectionOffset) {
      issues.push(`.resources value for ${JSON.stringify(name.value)} has an invalid data offset.`);
      continue;
    }
    if (seen.has(name.value)) issues.push(`.resources contains duplicate name ${JSON.stringify(name.value)}.`);
    seen.add(name.value);
    names.push({ value: name.value, dataOffset: table.dataSectionOffset + dataOffset });
  }
  return names;
};

const readResourceValue = async (
  payload: Uint8Array,
  table: ResourceValueTable,
  name: { value: string; dataOffset: number }
): Promise<PeClrManagedResourceValue> => {
  const type = readSevenBitEncodedInt(payload, name.dataOffset);
  if (!type) {
    return { name: name.value, type: "Unknown", value: null, opaque: true, issues: ["Resource value type code is truncated."] };
  }
  return decodeDotNetResourceValue(
    payload,
    type,
    name.value,
    table.version,
    table.userTypes
  );
};
