import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { skipLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";
import { readLegacyCodeViewFields, type LegacyCodeViewField } from "./legacy-codeview-fields.js";
import { readLegacyCodeViewTypeStrings } from "./legacy-codeview-type-strings.js";

export interface LegacyCodeViewTypes {
  kind: "types";
  records: { type: number; name?: string; uniqueName?: string; members?: LegacyCodeViewField[]; strings?: string[] }[];
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

const readType = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewTypes["records"][number]> => {
  const type = await reader.uint16(2);
  if (type === 0x204 || type === 0x1203) return { type,
    members: await readLegacyCodeViewFields(reader.subsection(4, reader.size - 4)) };
  try {
    const strings = await readLegacyCodeViewTypeStrings(reader, type);
    if (strings !== undefined) return { type, strings };
    const numeric = NUMERIC_OFFSETS.get(type);
    const offset = numeric == null ? NAME_OFFSETS.get(type) : await skipLegacyCodeViewNumeric(reader, numeric);
    if (offset == null) return { type };
    return type >= 0x1500 ? await readUtf8TypeName(reader, type, offset) :
      { type, name: (await reader.pascal(offset)).name };
  } catch (error) { reader.warn(`CodeView type name: ${String(error)}`); return { type }; }
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
      if (record) records.push(record);
    } catch (error) { reader.warn(`CodeView type ${index}: ${String(error)}`); }
  }
  return { kind: "types", records };
};

export const readLegacyCodeViewModuleTypes = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewTypes> => {
  const signature = await reader.uint32(0);
  if (![1, 2, 4].includes(signature)) throw new Error(`Unsupported CodeView type stream signature ${signature}.`);
  const records: LegacyCodeViewTypes["records"] = [];
  let offset = 4;
  while (offset < reader.size) {
    try {
      const value = await readTypeAt(reader, offset);
      records.push(value.record);
      offset = value.end;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "types", records };
};
