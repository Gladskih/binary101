import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { skipLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";

export interface LegacyCodeViewTypes { kind: "types"; records: { type: number; name?: string }[]; }

// Offset of size numeric leaf, or name for enum/alias; includes record length.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const NUMERIC_OFFSETS = new Map([
  [3, 8], [4, 14], [5, 14], [6, 10], [0x1003, 12], [0x1004, 20], [0x1005, 20], [0x1006, 12],
  [0x1503, 12], [0x1504, 20], [0x1505, 20], [0x1506, 12], [0x1519, 20]
]);
const NAME_OFFSETS = new Map([[7, 12], [0x1007, 16], [0x1010, 8], [0x1507, 16], [0x150a, 8]]);

const readType = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewTypes["records"][number]> => {
  const type = await reader.uint16(2);
  const numeric = NUMERIC_OFFSETS.get(type);
  const offset = numeric == null ? NAME_OFFSETS.get(type) : await skipLegacyCodeViewNumeric(reader, numeric);
  if (offset == null) return { type };
  const name = type >= 0x1500 ? await reader.utf8(offset) : (await reader.pascal(offset)).name;
  return { type, name };
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
  const decoded = new Map<number, LegacyCodeViewTypes["records"][number]>();
  for (let index = 0; index < count; index++) {
    try {
      const offset = await reader.uint32(8 + index * 4);
      let record = decoded.get(offset);
      if (!record) {
        // TIS Symbol and Type Information 7.4: NB07/08 use subsection-relative
        // offsets; NB09 and later use offsets from the first type record.
        // https://openwatcom.org/ftp/devel/docs/CodeView.pdf
        const origin = signature === "NB07" || signature === "NB08" ? 0 : base;
        record = (await readTypeAt(reader, origin + offset)).record;
        decoded.set(offset, record);
      }
      records.push(record);
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
