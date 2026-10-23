import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { skipLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";
import { readLegacyCodeViewFields, type LegacyCodeViewField } from "./legacy-codeview-fields.js";
import { readLegacyCodeViewTypeStrings } from "./legacy-codeview-type-strings.js";
import { readLegacyCodeViewEmbeddedSymbol, type LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";
import { readLegacyCodeViewPointerBase } from "./legacy-codeview-pointer-base.js";
import { readCodeViewTypeShape, type CodeViewTypeShape } from "./legacy-codeview-type-shapes.js";

export interface LegacyCodeViewTypeRecord {
  type: number;
  index?: number;
  shape?: CodeViewTypeShape;
  name?: string;
  uniqueName?: string;
  members?: LegacyCodeViewField[];
  strings?: string[];
  symbols?: LegacyCodeViewSymbol[];
}

export interface LegacyCodeViewTypes {
  kind: "types";
  encoding?: "c6" | "hll";
  records: LegacyCodeViewTypeRecord[];
}

// Offsets of size numeric leaves and inline names, including the record length.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const NUMERIC_OFFSETS = new Map([
  [3, 8], [4, 14], [5, 14], [6, 10], [0x1003, 12], [0x1004, 20], [0x1005, 20], [0x1006, 12],
  [0x1503, 12], [0x1504, 20], [0x1505, 20], [0x1506, 12], [0x1519, 20],
  [0x1516, 16], [0x151b, 12], [0x151c, 21] // MATRIX has a one-byte CV_matrixattr_t.
]);
const NAME_OFFSETS = new Map([[7, 12], [0x1007, 16], [0x1010, 8], [0x1507, 16], [0x150a, 8],
  [0x11, 8], [0x100c, 12], [0x1508, 12]]);

const readUtf8TypeName = async (reader: LegacyCodeViewReader, type: number, offset: number) => {
  const { name, end } = await reader.utf8Name(offset);
  // CV_prop_t.hasuniquename (bit 9) appends a second string to these UDT leaves.
  // Same cvinfo.h source as the record offsets above.
  if (![0x1504, 0x1505, 0x1506, 0x1507, 0x1519].includes(type) ||
      !(await reader.uint16(6) & 0x200)) return { type, name };
  try { return { type, name, uniqueName: await reader.utf8(end) }; }
  catch (error) { reader.warn(`CodeView decorated type name: ${String(error)}`); return { type, name }; }
};

const readTypeName = async (reader: LegacyCodeViewReader, type: number): Promise<LegacyCodeViewTypeRecord> => {
  const numeric = NUMERIC_OFFSETS.get(type);
  const offset = numeric == null ? NAME_OFFSETS.get(type) : await skipLegacyCodeViewNumeric(reader, numeric);
  if (offset == null) return { type };
  return type >= 0x1500 ? readUtf8TypeName(reader, type, offset) :
    { type, name: (await reader.pascal(offset)).name };
};

const readTypeContent = async (reader: LegacyCodeViewReader, type: number): Promise<LegacyCodeViewTypeRecord> => {
  if (type === 0x204 || type === 0x1203) return { type,
    members: await readLegacyCodeViewFields(reader.subsection(4, reader.size - 4)) };
  if (type === 2 || type === 0x1002) return { type, ...await readLegacyCodeViewPointerBase(reader, type) };
  // TIS 3.4 LF_REFSYM stores a complete length-prefixed symbol at offset 4.
  // https://openwatcom.org/ftp/devel/docs/CodeView.pdf
  if (type === 0x20c) return { type, symbols: await readLegacyCodeViewEmbeddedSymbol(reader, 4) };
  const strings = await readLegacyCodeViewTypeStrings(reader, type);
  if (strings !== undefined) return { type, strings };
  return readTypeName(reader, type);
};

const readType = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewTypeRecord> => {
  const type = await reader.uint16(2);
  let shape: CodeViewTypeShape | undefined;
  try {
    shape = await readCodeViewTypeShape(reader, type);
    const record = await readTypeContent(reader, type);
    return shape ? { ...record, shape } : record;
  } catch (error) {
    reader.warn(`CodeView type name: ${String(error)}`);
    return shape ? { type, shape } : { type };
  }
};

const globalTypeOffset = (signature: string, base: number, offset: number): number => {
  // TIS 7.4: NB07/08 offsets are subsection-relative; NB09+ are record-base-relative.
  // https://openwatcom.org/ftp/devel/docs/CodeView.pdf
  const target = (signature === "NB07" || signature === "NB08" ? 0 : base) + offset;
  if (target < base) throw new Error("CodeView type offset overlaps the header or offset table.");
  return target;
};

const readTypeAt = async (reader: LegacyCodeViewReader, offset: number) => {
  const length = await reader.uint16(offset);
  if (length < 2) throw new Error("Invalid CodeView type record length.");
  await reader.view(offset, length + 2);
  return { record: await readType(reader.subsection(offset, length + 2)), end: offset + length + 2 };
};

export const readLegacyCodeViewGlobalTypes = async (
  reader: LegacyCodeViewReader, signature = "NB09"
): Promise<LegacyCodeViewTypes> => {
  const count = await reader.uint32(4);
  const base = 8 + count * 4;
  if (base > reader.size) throw new Error("CodeView global type offsets are truncated.");
  const records: LegacyCodeViewTypes["records"] = [];
  const decoded = new Map<number, LegacyCodeViewTypes["records"][number] | undefined>();
  for (let index = 0; index < count; index++) {
    try {
      const offset = await reader.uint32(8 + index * 4);
      if (!decoded.has(offset)) {
        decoded.set(offset, undefined);
        decoded.set(offset, (await readTypeAt(reader, globalTypeOffset(signature, base, offset))).record);
      }
      const record = decoded.get(offset);
      // OMFGlobalTypes slots retain their identity even when earlier offsets are invalid.
      if (record) records.push({ ...record, index: 0x1000 + index });
    } catch (error) { reader.warn(`CodeView type ${index}: ${String(error)}`); }
  }
  return { kind: "types", records };
};

// LF_PRECOMP/type servers reference external namespaces. Do not invent local
// indices for records after such an import without loading its actual type table.
const EXTERNAL_TYPE_TABLES = new Set([0x13, 0x100e, 0x1509, 0x16, 0x1501, 0x1515, 0x14]);

const nextTypeIndex = (record: LegacyCodeViewTypeRecord, index: number | undefined,
  warn: (message: string) => void): number | undefined => {
  if (index === undefined || EXTERNAL_TYPE_TABLES.has(record.type)) return undefined;
  if (index === 0xffffffff) {
    warn("CodeView type index space is exhausted; later indices are unresolved.");
    return undefined;
  }
  if (record.type !== 0x200 && record.type !== 0x1200) return index + 1;
  if (record.shape?.kind === "skip" && record.shape.nextIndex > index) return record.shape.nextIndex;
  warn("CodeView LF_SKIP has no valid forward type index; later indices are unresolved.");
  return undefined;
};

export const readLegacyCodeViewModuleTypes = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewTypes> => {
  const signature = await reader.uint32(0);
  if (![1, 2, 4].includes(signature)) throw new Error(`Unsupported CodeView type stream signature ${signature}.`);
  const records: LegacyCodeViewTypes["records"] = [];
  let offset = 4;
  let index: number | undefined = 0x1000;
  while (offset < reader.size) {
    try {
      const value = await readTypeAt(reader, offset);
      records.push(index === undefined || EXTERNAL_TYPE_TABLES.has(value.record.type)
        ? value.record : { ...value.record, index });
      index = nextTypeIndex(value.record, index, reader.warn);
      offset = value.end;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "types", records };
};
