import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { Td32TypeBody } from "./td32-type-body-types.js";
import type { Td32TypeMethod } from "./td32-type-member-types.js";
import { readTd32TypeFields } from "./td32-type-fields.js";

// TypMList.Read and Program's VtabShape/field-list dispatch; Pascal property reader.
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const readMethod = async (reader: LegacyCodeViewReader) => {
  const view = await reader.view(0, 10);
  const attributes = view.getUint16(0, true);
  const method: Td32TypeMethod = { attributes, methodType: view.getUint32(2, true),
    browserOffset: view.getUint32(6, true) };
  const property = attributes >> 2 & 7;
  if (property === 7) throw new Error("TD32 reserved method property has an unknown entry width.");
  if (attributes & 0xc000) reader.warn("TD32 method attributes contain reserved bits.");
  if (property !== 4 && property !== 6) return { method, end: 10 };
  method.vtableOffset = (await reader.view(10, 4)).getInt32(0, true);
  return { method, end: 14 };
};
const readMethods = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const methods: Td32TypeMethod[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const decoded = await readMethod(reader.subsection(offset, reader.size - offset));
      methods.push(decoded.method);
      offset += decoded.end;
    } catch (error) { reader.warn(`TD32 method list: ${String(error)}`); break; }
  }
  return { methods };
};
const readVtableShape = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const count = await reader.uint16(0);
  const view = await reader.view(2, Math.ceil(count / 2));
  const descriptors = Array.from({ length: count }, (_, index) =>
    view.getUint8(Math.floor(index / 2)) >> (index % 2 * 4) & 15);
  if (descriptors.some(value => value > 6)) reader.warn("TD32 vtable shape contains unrecognized descriptors.");
  return { descriptors };
};
const readProperty = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 22);
  // Both decoders agree on these stored slots, but disagree on accessor-flag meanings.
  // https://github.com/csm101/delphi-visual-studio-code-debugger/blob/580b258063a37e6e6bd93a9a7593e0b8cc8a9d06/docs/TD32_FORMAT_NOTES.md
  return { underlyingType: view.getUint32(0, true), attributes: view.getUint16(4, true),
    indexType: view.getUint32(6, true), propertyIndex: view.getInt32(10, true),
    readerValue: view.getUint32(14, true), writerValue: view.getUint32(18, true) };
};
const readClosure = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 6);
  // TypPasClosure.Read conditionally skips parmCount because of a commented throw.
  // Retain the common prefix and the exact remaining bytes, rather than emulate that bug.
  const tail = await reader.view(6, reader.size - 6);
  return { returnType: view.getUint32(0, true), callingConvention: view.getUint8(4),
    functionAttributes: view.getUint8(5),
    closureTail: Array.from(new Uint8Array(tail.buffer, tail.byteOffset, tail.byteLength)) };
};
const READERS: Readonly<Partial<Record<number, (reader: LegacyCodeViewReader) => Promise<Td32TypeBody>>>> = {
  10: readVtableShape, 0x204: async reader => ({ fields: await readTd32TypeFields(reader) }),
  0x207: readMethods, 0x34: readClosure, 0x35: readProperty
};

export const readTd32ExtendedTypeBody = async (reader: LegacyCodeViewReader,
  type: number): Promise<Td32TypeBody | undefined> => READERS[type]?.(reader);
