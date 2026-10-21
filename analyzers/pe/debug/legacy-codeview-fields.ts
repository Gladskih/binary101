import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { skipLegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";

export interface LegacyCodeViewField { type: number; name?: string; continuation?: number; }

// All offsets are from the subrecord's leaf tag (there is no per-field length).
// lfMember, lfSTMember, lfMethod, lfNestType, lfOneMethod and their 16t/ST/SZ variants:
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2478
const NAME_OFFSETS = new Map([
  [0x404, 4], [0x407, 6], [0x408, 6], [0x409, 4],
  [0x1403, 8], [0x1406, 8], [0x1407, 8], [0x1408, 8], [0x140d, 8], [0x140e, 8], [0x140f, 2],
  [0x150c, 8], [0x150e, 8], [0x150f, 8], [0x1510, 8], [0x1512, 8], [0x1513, 8], [0x1514, 2]
]);
const NUMERIC_NAMES = new Map([[0x403, 4], [0x406, 6], [0x1405, 8], [0x1502, 4], [0x150d, 8]]);
const METHOD_NAMES = new Map([[0x40c, 6], [0x140b, 8], [0x1511, 8]]);
const FIXED_SIZES = new Map([[0x405, 4], [0x40a, 4], [0x40b, 4], [0x40d, 8],
  [0x1404, 8], [0x1409, 8], [0x140a, 8], [0x140c, 12]]);
const BASE_OFFSETS = new Map([[0x400, 6], [0x1400, 8], [0x151a, 8]]);
const VIRTUAL_BASE_OFFSETS = new Map([[0x401, 8], [0x402, 8], [0x1401, 12], [0x1402, 12]]);
const PADDED_PREFIXES = new Set([0x1403, 0x1404, 0x1408, 0x1409, 0x140a, 0x140c, 0x150c, 0x1510]);

const nameOffset = async (reader: LegacyCodeViewReader, type: number): Promise<number | undefined> => {
  const numeric = NUMERIC_NAMES.get(type);
  if (numeric !== undefined) return skipLegacyCodeViewNumeric(reader, numeric);
  const method = METHOD_NAMES.get(type);
  if (method !== undefined) {
    // CV_fldattr_t.mprop is bits 2..4; only intro/pureintro add a DWORD vbaseoff.
    const property = await reader.uint16(2) >>> 2 & 7;
    if (property === 7) reader.warn("CodeView method property is reserved.");
    return method + ([4, 6].includes(property) ? 4 : 0);
  }
  return NAME_OFFSETS.get(type);
};

const unnamedEnd = async (reader: LegacyCodeViewReader, type: number): Promise<number> => {
  const fixed = FIXED_SIZES.get(type);
  if (fixed !== undefined) { await reader.view(0, fixed); return fixed; }
  const base = BASE_OFFSETS.get(type);
  if (base !== undefined) return skipLegacyCodeViewNumeric(reader, base);
  const virtualBase = VIRTUAL_BASE_OFFSETS.get(type);
  if (virtualBase !== undefined) return skipLegacyCodeViewNumeric(reader,
    await skipLegacyCodeViewNumeric(reader, virtualBase));
  throw new Error(`Unsupported CodeView field kind ${type}; remaining field bytes were not decoded.`);
};

const readField = async (reader: LegacyCodeViewReader) => {
  const type = await reader.uint16(0);
  if (PADDED_PREFIXES.has(type) && await reader.uint16(2) !== 0) reader.warn("CodeView field reserved padding is nonzero.");
  const offset = await nameOffset(reader, type);
  if (offset !== undefined) {
    const text = type >= 0x1500 ? await reader.utf8Name(offset) : await reader.pascal(offset);
    return { record: { type, name: text.name }, end: text.end };
  }
  const end = await unnamedEnd(reader, type);
  const record: LegacyCodeViewField = { type };
  if (type === 0x405) record.continuation = await reader.uint16(2);
  if (type === 0x1404) record.continuation = await reader.uint32(4);
  return { record, end };
};

const skipPadding = async (reader: LegacyCodeViewReader, offset: number, marker: number): Promise<number> => {
  const count = marker & 15;
  if (!count) throw new Error("CodeView LF_PAD0 cannot advance the field list.");
  // TIS "(0x0204) Field List" specifies the leading marker's low nibble as the skip
  // count; it does not require any particular values in the remaining bytes.
  // https://www.x-ways.net/winhex/kb/ff/PE_EXE.pdf#page=88
  await reader.view(offset, count);
  return offset + count;
};

export const readLegacyCodeViewFields = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewField[]> => {
  const fields: LegacyCodeViewField[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const marker = (await reader.view(offset, 1)).getUint8(0);
      if (marker >= 0xf0) { offset = await skipPadding(reader, offset, marker); continue; }
      const field = await readField(reader.subsection(offset, reader.size - offset));
      fields.push(field.record);
      offset += field.end;
    } catch (error) { reader.warn(`CodeView field list: ${String(error)}`); break; }
  }
  return fields;
};
