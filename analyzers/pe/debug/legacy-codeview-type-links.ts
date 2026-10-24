import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export type CodeViewTypeLinks =
  | { kind: "derived"; indices: number[] }
  | { kind: "buildInfo"; indices: number[] }
  | { kind: "stringList"; indices: number[] }
  | { kind: "vtablePath"; indices: number[] }
  | { kind: "vtable"; ownerType: number; baseTable: number; pointerOffset: number }
  | { kind: "stringId"; substrings: number }
  | { kind: "sourceLine"; typeIndex: number; source: number; line: number; module?: number };

// lfDerived[_16t], lfBuildInfo, lfStringId, lfUdt[Mod]SrcLine.
// Offsets include the length and leaf fields; a count is not always index-sized.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
// LF_SUBSTR_LIST uses a DWORD count, like LF_ARGLIST (TypeRecordMapping.cpp).
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/DebugInfo/CodeView/TypeRecordMapping.cpp
const INDEX_LISTS = new Map<number,
  readonly ["derived" | "buildInfo" | "stringList" | "vtablePath", 2 | 4, 2 | 4]>([
  [0x205, ["derived", 2, 2]], [0x1204, ["derived", 4, 4]],
  [0x12, ["vtablePath", 2, 2]], [0x100d, ["vtablePath", 4, 4]],
  [0x1603, ["buildInfo", 2, 4]], [0x1604, ["stringList", 4, 4]]
]);

/** Read a record's count at +4 and its contiguous index array after that count. */
export const readCodeViewIndexList = async (reader: LegacyCodeViewReader,
  countWidth: 2 | 4, indexWidth: 2 | 4): Promise<number[]> => {
  const header = await reader.view(4, countWidth);
  const count = countWidth === 2 ? header.getUint16(0, true) : header.getUint32(0, true);
  const data = await reader.view(4 + countWidth, count * indexWidth);
  const indices: number[] = [];
  for (let index = 0; index < count; index++) indices.push(indexWidth === 2
    ? data.getUint16(index * indexWidth, true) : data.getUint32(index * indexWidth, true));
  return indices;
};

const readSourceLine = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeLinks> => {
  const header = await reader.view(4, leaf === 0x1607 ? 14 : 12);
  return { kind: "sourceLine", typeIndex: header.getUint32(0, true), source: header.getUint32(4, true),
    line: header.getUint32(8, true), ...(leaf === 0x1607 ? { module: header.getUint16(12, true) } : {}) };
};

// lfVftable: class owner, base table and vfptr's byte offset within the object.
const readVtable = async (reader: LegacyCodeViewReader): Promise<CodeViewTypeLinks> => {
  const header = await reader.view(4, 12);
  return { kind: "vtable", ownerType: header.getUint32(0, true), baseTable: header.getUint32(4, true),
    pointerOffset: header.getUint32(8, true) };
};

/** Retain local type/ID links; module string-table offsets remain explicitly distinct. */
export const readCodeViewTypeLinks = async (reader: LegacyCodeViewReader,
  leaf: number): Promise<CodeViewTypeLinks | undefined> => {
  const list = INDEX_LISTS.get(leaf);
  if (list) return { kind: list[0], indices: await readCodeViewIndexList(reader, list[1], list[2]) };
  if (leaf === 0x151d) return readVtable(reader);
  if (leaf === 0x1605) return { kind: "stringId", substrings: await reader.uint32(4) };
  return leaf === 0x1606 || leaf === 0x1607 ? readSourceLine(reader, leaf) : undefined;
};
