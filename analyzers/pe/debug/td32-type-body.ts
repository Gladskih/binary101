import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";
import type { Td32TypeBody } from "./td32-type-body-types.js";

// Borland bodies use 32-bit type references but often retain 16-bit attributes/counts.
// Offsets below are payload-relative, excluding the length/leaf words.
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
// https://github.com/csm101/delphi-visual-studio-code-debugger/blob/580b258063a37e6e6bd93a9a7593e0b8cc8a9d06/docs/TD32_FORMAT_NOTES.md
const readModifier = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 6);
  return { attributes: view.getUint16(0, true), targetType: view.getUint32(2, true) };
};

const readPointer = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const body = await readModifier(reader);
  // TypPointer.Read stores member-pointer attributes followed by its class type.
  const mode = (body.attributes! >> 5) & 7;
  if (mode === 2 || mode === 3) {
    const view = await reader.view(6, 6);
    return { ...body, memberAttributes: view.getUint16(0, true), classType: view.getUint32(2, true) };
  }
  return body;
};

const readStructure = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 20);
  const body: Td32TypeBody = { count: view.getUint16(0, true), fieldList: view.getUint32(2, true),
    attributes: view.getUint16(6, true), relation12: view.getUint32(8, true),
    relation16: view.getUint32(12, true), relation20: view.getUint32(16, true) };
  // TypStruct.Read reads a numeric leaf after the name index at payload+20.
  // The debugger describes a u16 size; numeric immediates agree with that encoding.
  try {
    const { end: _end, ...byteSize } = await readLegacyCodeViewNumeric(reader, 24);
    body.byteSize = byteSize;
  } catch (error) { reader.warn(`TD32 type size: ${String(error)}`); }
  return body;
};

const readEnum = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 14);
  return { count: view.getUint16(0, true), underlyingType: view.getUint32(2, true),
    fieldList: view.getUint32(6, true), relation14: view.getUint32(10, true) };
};

const procedureFields = (view: DataView, offset: number): Td32TypeBody => ({
  callingConvention: view.getUint8(offset), functionAttributes: view.getUint8(offset + 1),
  parameterCount: view.getUint16(offset + 2, true), argumentList: view.getUint32(offset + 4, true)
});

const readProcedure = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 12);
  return { returnType: view.getUint32(0, true), ...procedureFields(view, 4) };
};

const readMemberFunction = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 24);
  return { returnType: view.getUint32(0, true), classType: view.getUint32(4, true),
    thisType: view.getUint32(8, true), ...procedureFields(view, 12),
    thisAdjustment: view.getInt32(20, true) };
};

const readArguments = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const count = await reader.uint16(0);
  const view = await reader.view(2, count * 4);
  return { argumentTypes: Array.from({ length: count }, (_, index) => view.getUint32(index * 4, true)) };
};

const readBitField = async (reader: LegacyCodeViewReader): Promise<Td32TypeBody> => {
  const view = await reader.view(0, 6);
  return { bitLength: view.getUint8(0), bitPosition: view.getUint8(1), underlyingType: view.getUint32(2, true) };
};

type BodyDecoder = (reader: LegacyCodeViewReader) => Promise<Td32TypeBody>;
const BODY_DECODERS: Readonly<Partial<Record<number, BodyDecoder>>> = {
  1: readModifier, 2: readPointer, 4: readStructure, 5: readStructure, 7: readEnum,
  8: readProcedure, 9: readMemberFunction, 0x201: readArguments, 0x206: readBitField
};

/** The enclosing record survives a truncated body; its warning remains visible. */
export const readTd32TypeBody = async (
  reader: LegacyCodeViewReader, type: number
): Promise<Td32TypeBody | undefined> => {
  try { return await BODY_DECODERS[type]?.(reader); }
  catch (error) { reader.warn(`TD32 type body ${type}: ${String(error)}`); return undefined; }
};
