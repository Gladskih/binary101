import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewSymbolName } from "./legacy-codeview-symbol-names.js";

export interface LegacyCodeViewSymbols { kind: "symbols"; records: { type: number; name?: string }[]; }

export const readLegacyCodeViewSymbols = async (
  reader: LegacyCodeViewReader, start: number, end: number
): Promise<LegacyCodeViewSymbols> => {
  const records: LegacyCodeViewSymbols["records"] = [];
  for (let offset = start; offset < end;) {
    try {
      const length = await reader.uint16(offset);
      if (length < 2 || length + 2 > end - offset) throw new Error("Invalid CodeView symbol record length.");
      const type = await reader.uint16(offset + 2);
      let name: string | null = null;
      try { name = await readLegacyCodeViewSymbolName(reader.subsection(offset, length + 2), type); }
      catch (error) { reader.warn(`CodeView symbol ${type}: ${String(error)}`); }
      records.push(name == null ? { type } : { type, name });
      offset += length + 2;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "symbols", records };
};

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
  return readLegacyCodeViewSymbols(reader, 16, 16 + size);
};

export const readLegacyCodeViewModuleSymbols = async (
  reader: LegacyCodeViewReader
): Promise<LegacyCodeViewSymbols> => {
  const signature = await reader.uint32(0);
  if (![1, 2, 4].includes(signature)) throw new Error(`Unsupported CodeView symbol stream signature ${signature}.`);
  return readLegacyCodeViewSymbols(reader, 4, reader.size);
};
