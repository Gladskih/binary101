import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

// Record-relative string offsets include the two-byte record length. Old ST
// leaves are byte-counted ANSI; leaves beyond LF_ST_MAX use UTF-8 stringZ.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/DebugInfo/CodeView/TypeRecordMapping.cpp
const STRING_OFFSETS = new Map([
  [0x13, 12], [0x100e, 16], [0x1509, 16], // Precompiled type file
  [0x16, 12], [0x1501, 12], [0x1515, 24], // PDB type server
  [0x202, 6], [0x1202, 8], [0x150b, 8], // Default argument expression
  [0x1601, 12], [0x1602, 12], [0x1605, 8] // Function IDs and stored string IDs
]);

const readVtableStrings = async (reader: LegacyCodeViewReader): Promise<string[]> => {
  // lfVftable::len bounds Names, excluding any record padding. The first string
  // names the table; every subsequent string names a virtual method.
  const declaredLength = await reader.uint32(16);
  if (declaredLength > reader.size - 20) reader.warn("CodeView virtual table Names array is truncated.");
  const length = Math.min(declaredLength, reader.size - 20);
  const names = reader.subsection(20, length);
  const strings: string[] = [];
  let offset = 0;
  while (offset < length) {
    try {
      const value = await names.utf8Name(offset);
      strings.push(value.name);
      offset = value.end;
    } catch (error) { reader.warn(`CodeView virtual table name: ${String(error)}`); break; }
  }
  if (length === 0) reader.warn("CodeView virtual table Names array has no table name.");
  return strings;
};

/** Retain actual stored strings; type/ID references are not expanded into guessed names. */
export const readLegacyCodeViewTypeStrings = async (
  reader: LegacyCodeViewReader, type: number
): Promise<string[] | undefined> => {
  if (type === 0x151d) return readVtableStrings(reader);
  const offset = STRING_OFFSETS.get(type);
  if (offset == null) return undefined;
  return [type >= 0x1500 ? await reader.utf8(offset) : (await reader.pascal(offset)).name];
};
