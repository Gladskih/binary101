import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewTypes } from "./legacy-codeview-type-records.js";
import { HllTypeFields } from "./hll-type-fields.js";

type TypeRecord = LegacyCodeViewTypes["records"][number];

const QUALIFIER_MASKS = new Map([[0x40, 7], [0x41, 1], [0x42, 1], [0x45, 31], [0x46, 63],
  [0x49, 15], [0x51, 15], [0x53, 63], [0x54, 63], [0x57, 3], [0x5c, 31],
  [0x65, 3], [0x72, 3], [0x75, 63], [0x78, 15], [0x79, 4], [0x7a, 3]]);

const validateQualifier = (type: number, qualifier: number): void => {
  const enumerated = new Map([[0x55, [0, 2]], [0x56, [1, 2]], [0x60, [0, 1, 2, 3, 4, 5]],
    [0x62, [0, 1, 2]], [0x7f, [1, 2, 3, 4]]]).get(type);
  const valid = enumerated ? enumerated.includes(qualifier) : !(qualifier & ~(QUALIFIER_MASKS.get(type) ?? 0));
  if (!valid) throw new Error(`Unknown HLL type ${type} qualifier ${qualifier}.`);
};

// IBM HLL Type Table Entry Definitions, figures 32-61. Fixed prefixes are
// consumed structurally; bytes resembling strings inside numeric fields are not names.
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
const readClass = async (fields: HllTypeFields, record: TypeRecord, qualifier: number): Promise<void> => {
  await fields.skip(8);
  record.name = await fields.name();
  if (qualifier & 2) { await fields.skip(4); record.strings = [await fields.name()]; }
};

const readMember = async (fields: HllTypeFields, record: TypeRecord, qualifier: number): Promise<void> => {
  await fields.skip(3);
  await fields.span();
  if (qualifier & 1) record.strings = [await fields.name()];
  record.name = await fields.name();
};

const readMethod = async (fields: HllTypeFields, record: TypeRecord, qualifier: number): Promise<void> => {
  await fields.skip(4);
  if (qualifier & 16) await fields.span();
  record.name = await fields.name();
};

const readList = async (fields: HllTypeFields, record: TypeRecord, qualifier: number): Promise<void> => {
  record.strings = [];
  while (fields.offset < fields.reader.size) {
    if (qualifier === 4) await fields.skip(1); // Argument passing flags.
    if (qualifier === 1 || qualifier === 4) await fields.index();
    else { record.strings.push(await fields.string()); await fields.span(); }
  }
};

const readText = async (fields: HllTypeFields, record: TypeRecord): Promise<void> => {
  const size = await fields.span();
  if (size < 0) throw new Error("Negative HLL text size.");
  record.strings = [await fields.reader.ansiBytes(fields.offset, size)];
  fields.offset += size;
};

const readEnum = async (fields: HllTypeFields, record: TypeRecord): Promise<void> => {
  await fields.index(); await fields.index(); await fields.span(); await fields.span();
  record.name = await fields.string();
};

const readStructure = async (fields: HllTypeFields, record: TypeRecord): Promise<void> => {
  await fields.skip(6); await fields.index(); await fields.index();
  record.name = await fields.string();
};

const readArray = async (fields: HllTypeFields, record: TypeRecord): Promise<void> => {
  await fields.skip(4); await fields.index(); await fields.index();
  record.name = await fields.string();
};

const readPointer = async (fields: HllTypeFields, record: TypeRecord): Promise<void> => {
  await fields.index();
  if (fields.offset < fields.reader.size) record.name = await fields.string();
};

const readSubrange = async (fields: HllTypeFields, record: TypeRecord): Promise<void> => {
  await fields.skip(2); await fields.span(); await fields.span();
  record.name = await fields.pascal();
};

const readStringSize = async (fields: HllTypeFields, _record: TypeRecord, qualifier: number): Promise<void> => {
  if (qualifier !== 2) await fields.span(); // Adjustable strings/areas have an external descriptor.
};

type TypeDecoder = (fields: HllTypeFields, record: TypeRecord, qualifier: number) => Promise<void>;
const DECODERS: Partial<Record<number, TypeDecoder>> = {
  0x40: readClass, 0x42: async (fields, record) => { await fields.skip(2); record.name = await fields.name(); },
  0x41: async fields => { await fields.skip(3); await fields.span(); },
  0x43: async fields => { await fields.skip(5); }, 0x45: readMethod, 0x46: readMember,
  0x48: async fields => { await fields.skip(2); }, 0x49: async fields => { await fields.skip(6); },
  0x51: async fields => { await fields.skip(4); },
  0x52: async (fields, record) => { await fields.skip(2); record.name = await fields.pascal(); },
  0x53: async fields => { await fields.skip(4); await fields.index(); await fields.index(); },
  0x54: async fields => { await fields.skip(4); await fields.index(); await fields.index(); },
  0x55: readStringSize, 0x56: async () => {},
  0x57: async (fields, record) => { await fields.skip(4); record.name = await fields.pascal(); },
  0x59: readText, 0x5c: async (fields, _record, qualifier) => {
    if (!(qualifier & 16)) { await fields.skip(1); await fields.span(); }
  },
  0x5d: async (fields, record) => { await fields.index(); record.name = await fields.string(); },
  0x60: readStringSize, 0x61: readText, 0x62: readStringSize, 0x65: async () => {}, 0x67: async () => {},
  0x6f: readSubrange, 0x72: async () => {},
  0x75: async fields => { await fields.skip(4); await fields.index(); await fields.index(); },
  0x78: readArray, 0x79: readStructure, 0x7a: readPointer, 0x7b: readEnum, 0x7f: readList
};

const readType = async (reader: LegacyCodeViewReader, record: TypeRecord, qualifier: number): Promise<void> => {
  const decode = DECODERS[record.type];
  if (!decode) throw new Error(`Unknown HLL type ${record.type}.`);
  validateQualifier(record.type, qualifier);
  const fields = new HllTypeFields(reader);
  await decode(fields, record, qualifier);
  if (fields.offset !== reader.size) reader.warn(`HLL type ${record.type} has trailing bytes.`);
};

export const readHllTypes = async (reader: LegacyCodeViewReader, version: number): Promise<LegacyCodeViewTypes> => {
  const records: TypeRecord[] = [];
  if (![0x100, 0x200, 0x300, 0x400].includes(version)) {
    reader.warn(`Unsupported HLL type format version ${version}.`);
    return { kind: "types", encoding: "hll", records };
  }
  const prefix = version === 0x100 ? 1 : 0; // V1 linkage byte was removed in V2.
  let offset = 0;
  while (offset < reader.size) {
    try {
      const header = await reader.view(offset, prefix + 4);
      const size = header.getUint16(prefix, true);
      if (size < 2 || size > reader.size - offset - prefix - 2) throw new Error("Invalid HLL type record length.");
      const record: TypeRecord = { type: header.getUint8(prefix + 2) };
      records.push(record);
      try { await readType(reader.subsection(offset + prefix + 4, size - 2), record, header.getUint8(prefix + 3)); }
      catch (error) { reader.warn(`HLL type ${record.type}: ${String(error)}`); }
      offset += prefix + size + 2;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "types", encoding: "hll", records };
};
