import type { TypeLibraryReader } from "./reader.js";
import type { MsftTypeDescriptors } from "./descriptors.js";
import { readCustomData, readValue } from "./values.js";
import type {
  TypeLibraryFunction, TypeLibraryVariable, TypeLibraryParameter
} from "./types.js";

// MSFT_DoFuncs / MSFT_DoVars (including FKCCIC masks, not the reversed header comment).
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
const readParameters = (
  reader: TypeLibraryReader, descriptors: MsftTypeDescriptors, start: number, size: number
): TypeLibraryParameter[] => {
  const count = reader.view.getUint16(start + 20, true);
  const flags = reader.view.getUint32(start + 16, true);
  const defaultBytes = flags & 0x1000 ? count * 4 : 0;
  const prefix = size - count * 12 - defaultBytes;
  if (prefix < 24) {
    reader.warn("TYPELIB function parameter/default-value table is truncated.");
    return [];
  }
  return Array.from({ length: count }, (_, index) => {
    const parameter = start + size - count * 12 + index * 12;
    const parameterFlags = reader.view.getUint32(parameter + 8, true);
    return {
      name: reader.lookup(reader.names, reader.view.getInt32(parameter + 4, true), "name"),
      type: descriptors.read(reader.view.getInt32(parameter, true)), flags: parameterFlags,
      defaultValue: (parameterFlags & 0x20) && defaultBytes
        ? readValue(reader, reader.view.getInt32(start + prefix + index * 4, true)) : null,
      customData: (flags & 0x80) && prefix >= 56 + index * 4
        ? readCustomData(reader, reader.view.getInt32(start + 52 + index * 4, true)) : []
    };
  });
};

const readFunction = (
  reader: TypeLibraryReader, descriptors: MsftTypeDescriptors, start: number,
  size: number, name: string | null, id: number
): TypeLibraryFunction => {
  const view = reader.view;
  const flags = view.getUint32(start + 16, true);
  const prefix = size - view.getUint16(start + 20, true) * (flags & 0x1000 ? 16 : 12);
  return {
    name, id, type: descriptors.read(view.getInt32(start + 4, true)),
    flags: view.getUint16(start + 8, true), kind: flags & 7,
    invocation: (flags >>> 3) & 15, callingConvention: (flags >>> 8) & 15,
    vtableOffset: view.getUint16(start + 12, true) & ~1,
    optionalParameters: view.getInt16(start + 22, true),
    helpContext: prefix >= 28 ? view.getUint32(start + 24, true) : null,
    helpStringContext: prefix >= 48 ? view.getUint32(start + 44, true) : null,
    documentation: prefix >= 32
      ? reader.lookup(reader.strings, view.getInt32(start + 28, true), "string") : null,
    entry: prefix >= 36 ? (flags & 0x2000 ? view.getUint32(start + 32, true)
      : reader.lookup(reader.strings, view.getInt32(start + 32, true), "string")) : null,
    customData: (flags & 0x80) && prefix >= 52
      ? readCustomData(reader, view.getInt32(start + 48, true)) : [],
    parameters: readParameters(reader, descriptors, start, size)
  };
};

const readVariable = (
  reader: TypeLibraryReader, descriptors: MsftTypeDescriptors, start: number,
  size: number, name: string | null, id: number
): TypeLibraryVariable => {
  const view = reader.view;
  const kind = view.getUint16(start + 12, true);
  return {
    name, id, type: descriptors.read(view.getInt32(start + 4, true)),
    flags: view.getUint16(start + 8, true), kind,
    helpContext: size >= 24 ? view.getUint32(start + 20, true) : null,
    helpStringContext: size >= 40 ? view.getUint32(start + 36, true) : null,
    documentation: size >= 28
      ? reader.lookup(reader.strings, view.getInt32(start + 24, true), "string") : null,
    value: kind === 2 ? readValue(reader, view.getInt32(start + 16, true)) : null,
    instanceOffset: kind === 2 ? null : view.getUint32(start + 16, true),
    customData: size >= 36 ? readCustomData(reader, view.getInt32(start + 32, true)) : []
  };
};

export const readMembers = (
  reader: TypeLibraryReader, descriptors: MsftTypeDescriptors, offset: number,
  functionCount: number, variableCount: number
): { functions: TypeLibraryFunction[]; variables: TypeLibraryVariable[] } => {
  const functions: TypeLibraryFunction[] = [];
  const variables: TypeLibraryVariable[] = [];
  const count = functionCount + variableCount;
  if (!count) return { functions, variables };
  const table = readMemberTable(reader, offset, count);
  if (table === null) return { functions, variables };
  for (let index = 0; index < functionCount; index++) {
    const record = readMemberRecord(reader, offset, table, count, index, 0xffff);
    if (!record) continue;
    functions.push(inheritPropertyName(readFunction(reader, descriptors, record.start, record.size,
      reader.lookup(reader.names, record.nameOffset, "name"), record.id),
    functions.at(-1), record.nameOffset));
  }
  for (let index = functionCount; index < count; index++) {
    const record = readMemberRecord(reader, offset, table, count, index, 0xff);
    if (!record) continue;
    variables.push(readVariable(reader, descriptors, record.start, record.size,
      reader.lookup(reader.names, record.nameOffset, "name"), record.id));
  }
  return { functions, variables };
};

const readMemberTable = (reader: TypeLibraryReader, offset: number, count: number): number | null => {
  if (!reader.range(offset, 4)) {
    reader.warn("TYPELIB member data offset is outside the resource.");
    return null;
  }
  const length = reader.view.getUint32(offset, true);
  const table = offset + 4 + length;
  if (!reader.range(offset + 4, length) || !reader.range(table, count * 12)) {
    reader.warn("TYPELIB member records or index tables are truncated.");
    return null;
  }
  return table;
};

const readMemberRecord = (
  reader: TypeLibraryReader, offset: number, table: number, count: number, index: number, mask: number
): { start: number; size: number; nameOffset: number; id: number } | null => {
  const start = offset + 4 + reader.view.getUint32(table + count * 8 + index * 4, true);
  if (!reader.range(start, 4, table)) {
    reader.warn("TYPELIB member record offset is outside its data block.");
    return null;
  }
  const size = reader.view.getUint32(start, true) & mask;
  if (size < (mask === 0xffff ? 24 : 20) || !reader.range(start, size, table)) {
    reader.warn("TYPELIB member record is truncated or has an invalid size.");
    return null;
  }
  return { start, size,
    nameOffset: reader.view.getInt32(table + count * 4 + index * 4, true),
    id: reader.view.getInt32(table + index * 4, true) };
};

const inheritPropertyName = (
  member: TypeLibraryFunction, previous: TypeLibraryFunction | undefined, nameOffset: number
): TypeLibraryFunction => {
  // Property get/put pairs may reuse the preceding function's name.
  if (nameOffset === -1 && [2, 4, 8].includes(member.invocation) &&
    [2, 4, 8].includes(previous?.invocation ?? 0)) {
    return { ...member, name: previous?.name ?? null };
  }
  return member;
};
