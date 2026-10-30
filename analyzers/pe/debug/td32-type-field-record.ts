import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";
import type { Td32TypeField } from "./td32-type-member-types.js";

interface FieldRead { field: Omit<Td32TypeField, "type">; end: number; }
// Borland uses DWORD type/name references and browser offsets, unlike CV4.
// MemRealBaseClass/MemInstanceData/MemMethods/MemNestedType.Read and field dispatch:
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const readBase = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const view = await reader.view(0, 6);
  const { end, ...offset } = await readLegacyCodeViewNumeric(reader, 6);
  return { field: { targetType: view.getUint32(0, true), attributes: view.getUint16(4, true), offset }, end };
};
const readVirtualBase = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const view = await reader.view(0, 10);
  const { end: next, ...offset } = await readLegacyCodeViewNumeric(reader, 10);
  const { end, ...virtualBaseIndex } = await readLegacyCodeViewNumeric(reader, next);
  return { field: { targetType: view.getUint32(0, true), pointerType: view.getUint32(4, true),
    attributes: view.getUint16(8, true), offset, virtualBaseIndex }, end };
};
const readEnumerate = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const view = await reader.view(0, 10);
  const { end, ...value } = await readLegacyCodeViewNumeric(reader, 10);
  return { field: { attributes: view.getUint16(0, true), nameIndex: view.getUint32(2, true),
    browserOffset: view.getUint32(6, true), value }, end };
};
const readStatic = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const view = await reader.view(0, 14);
  return { field: { targetType: view.getUint32(0, true), attributes: view.getUint16(4, true),
    nameIndex: view.getUint32(6, true), browserOffset: view.getUint32(10, true) }, end: 14 };
};
const readMember = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const prefix = await readStatic(reader);
  const { end, ...offset } = await readLegacyCodeViewNumeric(reader, prefix.end);
  return { field: { ...prefix.field, offset }, end };
};
const readMethods = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const view = await reader.view(0, 10);
  return { field: { count: view.getUint16(0, true), targetType: view.getUint32(2, true),
    nameIndex: view.getUint32(6, true) }, end: 10 };
};
const readNested = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const view = await reader.view(0, 12);
  return { field: { targetType: view.getUint32(0, true), nameIndex: view.getUint32(4, true),
    browserOffset: view.getUint32(8, true) }, end: 12 };
};
const readVtablePointer = async (reader: LegacyCodeViewReader): Promise<FieldRead> => {
  const targetType = await reader.uint32(0);
  const { end, ...offset } = await readLegacyCodeViewNumeric(reader, 4);
  return { field: { targetType, offset }, end };
};
const READERS: Readonly<Partial<Record<number, (reader: LegacyCodeViewReader) => Promise<FieldRead>>>> = {
  0x400: readBase, 0x401: readVirtualBase, 0x402: readVirtualBase, 0x403: readEnumerate,
  0x405: async reader => ({ field: { targetType: await reader.uint32(0) }, end: 4 }),
  0x406: readMember, 0x407: readStatic, 0x408: readMethods, 0x409: readNested, 0x40a: readVtablePointer
};

export const readTd32TypeField = async (reader: LegacyCodeViewReader) => {
  const type = await reader.uint16(0);
  const decode = READERS[type];
  if (!decode) throw new Error(`Unsupported TD32 field kind ${type}; remaining field bytes were not decoded.`);
  const { field, end } = await decode(reader.subsection(2, reader.size - 2));
  return { field: { type, ...field }, end: end + 2 };
};
