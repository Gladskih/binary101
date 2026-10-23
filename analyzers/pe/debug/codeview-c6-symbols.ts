import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewSymbols } from "./legacy-codeview-symbols.js";
import type { LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";

// Microsoft C Developer's Toolkit, 1.3; dumpsym6.cpp/debsym.h (offset-width bit 7).
// https://www.pcjs.org/documents/books/mspl13/c/ctoolkit/
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym6.cpp
const OFFSET_PREFIXES = new Map([[0, 2], [1, 11], [4, 2], [5, 4], [11, 1], [12, 2], [15, 11]]);
const FIXED_PREFIXES = new Map([[2, 0], [13, 3], [17, 4], [18, 2], [22, 7]]);

const constantEnd = async (reader: LegacyCodeViewReader): Promise<number> => {
  const code = (await reader.view(4, 1)).getUint8(0);
  const size = code < 128 ? code : new Map([[133, 2], [134, 4], [135, 8],
    [136, 1], [137, 2], [138, 4], [139, 8]]).get(code);
  if (size === undefined) throw new Error(`Unknown C6 constant encoding ${code}.`);
  await reader.view(2, 3 + size);
  return 5 + size;
};

const readSymbolName = async (reader: LegacyCodeViewReader, record: LegacyCodeViewSymbol): Promise<void> => {
  const type = record.type & 0x7f;
  if (type === 16) return; // S_NOOP is arbitrary incremental-link padding.
  const relative = OFFSET_PREFIXES.get(type);
  const prefix = relative === undefined ? FIXED_PREFIXES.get(type) : relative + (record.type & 0x80 ? 4 : 2);
  if (prefix === undefined && type !== 14) throw new Error(`Unknown C6 symbol kind ${type}.`);
  const offset = type === 14 ? await constantEnd(reader) : 2 + prefix!;
  await reader.view(0, offset);
  if (offset === reader.size) return;
  const value = await reader.pascal(offset);
  record.name = value.name;
  if (value.end !== reader.size) reader.warn("C6 symbol has trailing bytes after its name.");
};

export const readCodeViewC6Symbols = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewSymbols> => {
  const records: LegacyCodeViewSymbol[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const header = await reader.view(offset, 2);
      const length = header.getUint8(0);
      if (!length || length + 1 > reader.size - offset) throw new Error("Invalid C6 symbol record length.");
      const record = { type: header.getUint8(1) };
      records.push(record);
      try { await readSymbolName(reader.subsection(offset, length + 1), record); }
      catch (error) { reader.warn(`C6 symbol ${record.type}: ${String(error)}`); }
      offset += length + 1;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "symbols", encoding: "c6", records };
};
