import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readTd32TypeBody } from "./td32-type-body.js";
import type { Td32TypeBody } from "./td32-type-body-types.js";

export interface Td32Types {
  kind: "types";
  version: number;
  records: { index: number; type: number; nameIndex?: number; body?: Td32TypeBody }[];
}
type TypeRecord = Omit<Td32Types["records"][number], "index">;
const NAME_OFFSETS: Readonly<Partial<Record<number, number>>> = { 4: 24, 5: 24, 7: 18 };

// Both implementations agree on version 1, subsection-relative offsets and
// class/structure/enum name indices. Array/union layouts differ; keep their
// record kinds without guessing which layout a producer used.
// https://github.com/csm101/delphi-visual-studio-code-debugger/blob/580b258063a37e6e6bd93a9a7593e0b8cc8a9d06/docs/TD32_FORMAT_NOTES.md#type-table-sst_types--sst_global_types
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const readType = async (reader: LegacyCodeViewReader, offset: number, tableEnd: number): Promise<TypeRecord> => {
  if (offset < tableEnd) throw new Error("TD32 type offset overlaps its header or offset table.");
  const header = await reader.view(offset, 4);
  const size = header.getUint16(0, true) + 2;
  if (size < 4 || size > reader.size - offset) throw new Error("TD32 type length exceeds subsection bounds.");
  const type = header.getUint16(2, true);
  const record: TypeRecord = { type };
  try {
    const nameOffset = NAME_OFFSETS[type];
    if (nameOffset !== undefined) record.nameIndex = await reader.subsection(offset, size).uint32(nameOffset);
  } catch (error) { reader.warn(`TD32 type name: ${String(error)}`); }
  const body = await readTd32TypeBody(reader.subsection(offset + 4, size - 4), type);
  return body ? { ...record, body } : record;
};

const warnAmbiguousLayout = (reader: LegacyCodeViewReader, type: number, warned: Set<number>): void => {
  if (type === 0x34 && !warned.has(type)) {
    warned.add(type);
    reader.warn("TD32 Pascal closure tails are retained as uninterpreted bytes; the published decoder's parameter-count handling is inconsistent.");
  }
  if (type !== 3 && type !== 6 || warned.has(type)) return;
  warned.add(type);
  reader.warn(`TD32 ${type === 3 ? "array" : "union"} type body layout is ambiguous between published decoders; only its record kind is decoded.`);
};

export const readTd32Types = async (reader: LegacyCodeViewReader): Promise<Td32Types> => {
  const header = await reader.view(0, 8);
  const version = header.getUint32(0, true);
  const count = header.getUint32(4, true);
  const result: Td32Types = { kind: "types", version, records: [] };
  if (version !== 1) { reader.warn(`Unsupported TD32 type table version ${version}.`); return result; }
  if (count * 4 > reader.size - 8) { reader.warn("TD32 type offset table is truncated."); return result; }
  const decoded = new Map<number, TypeRecord | undefined>();
  const warnedLayouts = new Set<number>();
  for (let index = 0; index < count; index++) {
    const offset = await reader.uint32(8 + index * 4);
    if (!decoded.has(offset)) {
      decoded.set(offset, undefined);
      try { decoded.set(offset, await readType(reader, offset, 8 + count * 4)); }
      catch (error) { reader.warn(String(error)); }
    }
    const record = decoded.get(offset);
    if (record) {
      result.records.push({ index, ...record });
      warnAmbiguousLayout(reader, record.type, warnedLayouts);
    }
  }
  return result;
};
