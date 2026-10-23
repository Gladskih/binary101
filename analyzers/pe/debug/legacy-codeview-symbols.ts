import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewSymbolRecords, type LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";
import { readLegacyCodeViewNameIndex, readLegacyCodeViewAddressIndex,
  type LegacyCodeViewIndex } from "./legacy-codeview-index.js";

export interface LegacyCodeViewSymbols {
  kind: "symbols";
  encoding?: "c6" | "hll";
  records: LegacyCodeViewSymbol[];
  nameIndex?: LegacyCodeViewIndex;
  addressIndex?: LegacyCodeViewIndex;
}

export const readLegacyCodeViewSymbols = async (
  reader: LegacyCodeViewReader, start: number, end: number
): Promise<LegacyCodeViewSymbols> => ({ kind: "symbols",
  records: await readLegacyCodeViewSymbolRecords(reader, start, end) });

// Packed global/public/static symbols start after OMFSymHash; the hash tables
// are indexes over these same records, not additional symbol definitions.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym7.cpp#L1214
export const readLegacyCodeViewGlobalSymbols = async (
  reader: LegacyCodeViewReader
): Promise<LegacyCodeViewSymbols> => {
  const header = await reader.view(0, 16);
  const size = header.getUint32(4, true);
  const total = 16 + size + header.getUint32(8, true) + header.getUint32(12, true);
  if (total > reader.size) reader.warn("CodeView symbol or address hash tables are truncated.");
  if (size > reader.size - 16) throw new Error("CodeView global symbol array is truncated.");
  const symbols = await readLegacyCodeViewSymbols(reader, 16, 16 + size);
  const nameSize = header.getUint32(8, true);
  const nameStart = 16 + size;
  const addressStart = nameStart + nameSize;
  const nameIndex = await readLegacyCodeViewNameIndex(reader.subsection(nameStart,
    Math.min(nameSize, reader.size - nameStart)), header.getUint16(0, true));
  const addressIndex = await readLegacyCodeViewAddressIndex(reader.subsection(addressStart,
    Math.max(0, Math.min(header.getUint32(12, true), reader.size - addressStart))), header.getUint16(2, true));
  return { ...symbols, ...(nameIndex ? { nameIndex } : {}), ...(addressIndex ? { addressIndex } : {}) };
};

export const readLegacyCodeViewModuleSymbols = async (
  reader: LegacyCodeViewReader
): Promise<LegacyCodeViewSymbols> => {
  const signature = await reader.uint32(0);
  if (![1, 2, 4].includes(signature)) throw new Error(`Unsupported CodeView symbol stream signature ${signature}.`);
  return readLegacyCodeViewSymbols(reader, 4, reader.size);
};
