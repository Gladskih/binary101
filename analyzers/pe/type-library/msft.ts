import type { ResourceTypeLibrarySegmentPreview } from "../resources/preview/types.js";
import { TypeLibraryReader, readMsftTables } from "./reader.js";
import { MsftTypeDescriptors } from "./descriptors.js";
import { readCustomData } from "./values.js";
import { readImports, readImportedTypes } from "./imports.js";
import { readMembers } from "./members.js";
import type { TypeLibraryAnalysis, TypeLibraryInterface, TypeLibraryType } from "./types.js";

// MSFT_TypeInfoBase is 100 bytes; cElement packs function and variable counts.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h
const readInterfaces = (
  reader: TypeLibraryReader, kind: number, count: number, first: number
): TypeLibraryInterface[] => {
  if (!count || first === -1) return [];
  if (kind !== 5) return [{ reference: first, flags: 0, customData: [] }];
  const result: TypeLibraryInterface[] = [];
  const seen = new Set<number>();
  let offset = first;
  for (let index = 0; index < count; index++) {
    if (seen.has(offset)) {
      reader.warn("TYPELIB implemented-interface chain contains a cycle.");
      break;
    }
    seen.add(offset);
    const start = reader.at("RefTab", offset, 16);
    if (start === null) break;
    result.push({ reference: reader.view.getInt32(start, true),
      flags: reader.view.getUint32(start + 4, true),
      customData: readCustomData(reader, reader.view.getInt32(start + 8, true)) });
    offset = reader.view.getInt32(start + 12, true);
  }
  return result;
};

const readType = (
  reader: TypeLibraryReader, descriptors: MsftTypeDescriptors, relative: number, start: number,
  members: ReturnType<typeof readMembers>
): TypeLibraryType => {
  const view = reader.view;
  const kind = view.getUint32(start, true) & 15;
  const datatype = view.getInt32(start + 84, true);
  return {
    reference: relative,
    kind, name: reader.lookup(reader.names, view.getInt32(start + 52, true), "name"),
    guid: reader.lookup(reader.guids, view.getInt32(start + 44, true), "GUID"),
    flags: view.getUint32(start + 48, true), version: view.getUint32(start + 56, true),
    size: view.getUint32(start + 80, true), alignment: (view.getUint32(start, true) >>> 11) & 31,
    vtableSize: view.getUint16(start + 78, true),
    documentation: reader.lookup(reader.strings, view.getInt32(start + 60, true), "string"),
    helpContext: view.getUint32(start + 68, true),
    helpStringContext: view.getUint32(start + 64, true),
    alias: kind === 6 ? descriptors.read(datatype) : null,
    dll: kind === 2 ? reader.lookup(reader.strings, datatype, "string") : null,
    customData: readCustomData(reader, view.getInt32(start + 72, true)),
    interfaces: readInterfaces(reader, kind, view.getUint16(start + 76, true), datatype),
    ...members
  };
};

const readTypes = (
  reader: TypeLibraryReader, descriptors: MsftTypeDescriptors
): TypeLibraryType[] => {
  const segment = reader.segment("TypeInfoTab");
  const count = reader.view.getUint32(32, true);
  if (!segment) {
    if (count) reader.warn("TYPELIB type information segment is missing or invalid.");
    return [];
  }
  if (segment.length < count * 100) reader.warn("TYPELIB type information table is truncated.");
  const result: TypeLibraryType[] = [];
  const memberBlocks = new Map<string, ReturnType<typeof readMembers>>();
  // Wine reads contiguous base records; validate the header's offset table against them.
  const offsets = 84 + (reader.view.getUint32(20, true) & 0x100 ? 4 : 0);
  for (let index = 0; index < Math.min(count, Math.floor(segment.length / 100)); index++) {
    const relative = index * 100;
    validateTypeOffset(reader, offsets + index * 4, relative);
    const start = segment.offset + relative;
    const offset = reader.view.getInt32(start + 4, true);
    const functions = reader.view.getUint16(start + 24, true);
    const variables = reader.view.getUint16(start + 26, true);
    const key = `${offset}:${functions}:${variables}`;
    const members = memberBlocks.get(key) ?? readMembers(reader, descriptors, offset, functions, variables);
    memberBlocks.set(key, members);
    result.push(readType(reader, descriptors, relative, start, members));
  }
  return result;
};

const validateTypeOffset = (reader: TypeLibraryReader, offset: number, expected: number): void => {
  if (reader.range(offset, 4) && reader.view.getUint32(offset, true) !== expected) {
    reader.warn("TYPELIB typeinfo offset table disagrees with the contiguous base records.");
  }
};

export const parseMsftAnalysis = (
  data: Uint8Array, segments: ResourceTypeLibrarySegmentPreview[], issues: string[]
): TypeLibraryAnalysis => {
  if (data.length < 84) {
    issues.push("TYPELIB MSFT header is truncated.");
    return { name: null, guid: null, documentation: null, helpFile: null, helpStringDll: null,
      helpContext: 0, helpStringContext: null,
      customData: [], imports: [], importedTypes: [], types: [] };
  }
  const reader = new TypeLibraryReader(data, segments, issues);
  readMsftTables(reader);
  const view = reader.view;
  return {
    name: reader.lookup(reader.names, view.getInt32(56, true), "name"),
    guid: reader.lookup(reader.guids, view.getInt32(8, true), "GUID"),
    documentation: reader.lookup(reader.strings, view.getInt32(36, true), "string"),
    helpContext: view.getUint32(44, true), helpStringContext: view.getUint32(40, true),
    helpFile: reader.lookup(reader.strings, view.getInt32(60, true), "string"),
    helpStringDll: (view.getUint32(20, true) & 0x100) && reader.range(84, 4)
      ? reader.lookup(reader.strings, view.getInt32(84, true), "string") : null,
    customData: readCustomData(reader, view.getInt32(64, true)),
    imports: readImports(reader), importedTypes: readImportedTypes(reader),
    types: readTypes(reader, new MsftTypeDescriptors(reader))
  };
};
