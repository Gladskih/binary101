import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewSymbols } from "./legacy-codeview-symbols.js";
import type { LegacyCodeViewSymbol } from "./legacy-codeview-symbol-records.js";
import { readHllLength, readHllName } from "./hll-strings.js";

// IBM HLL Symbol Scope Table figures 5-28; offsets start at the kind byte.
// CU_FUNC_NUM is explicitly reserved; WITH and SKIP have no defined contents.
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/watcom/h/hll.h
const NAME_OFFSETS = new Map([[0, 9], [1, 20], [4, 7], [5, 9], [6, 9], [11, 6],
  [13, 4], [15, 20], [18, 3], [19, 9], [20, 5], [21, 7], [22, 3], [23, 13],
  [25, 3], [26, 20], [27, 11], [28, 13], [29, 20], [30, 9], [32, 8], [33, 11]]);
const LONG_NAMES = new Set([6, 25, 26, 29, 30]);

const readCompiler = async (reader: LegacyCodeViewReader, record: LegacyCodeViewSymbol): Promise<void> => {
  const options = await reader.pascal(2);
  record.strings = [options.name];
  const date = await reader.pascal(options.end);
  record.strings.push(date.name);
  await reader.view(date.end, 11); // OS/2 DATETIME, as consumed by Open Watcom dumphll.c.
};

const nameOffset = async (reader: LegacyCodeViewReader, record: LegacyCodeViewSymbol): Promise<number> => {
  if (record.type === 24) return 1;
  if (record.type === 14) {
    const size = (await reader.view(3, 1)).getUint8(0);
    record.strings = [await reader.ansiBytes(4, size)];
    return 4 + size;
  }
  const offset = NAME_OFFSETS.get(record.type);
  if (offset === undefined) throw new Error(`Unknown HLL symbol kind ${record.type}.`);
  return offset;
};

const readSymbol = async (reader: LegacyCodeViewReader, record: LegacyCodeViewSymbol): Promise<void> => {
  if (record.type === 64) return readCompiler(reader, record);
  const fixedSize = new Map([[2, 1], [17, 5], [34, 7]]).get(record.type);
  if (fixedSize !== undefined) { await reader.view(0, fixedSize); return; }
  if ([12, 16, 65].includes(record.type)) return;
  const offset = await nameOffset(reader, record);
  await reader.view(0, offset);
  const value = LONG_NAMES.has(record.type) ? await readHllName(reader, offset) : await reader.pascal(offset);
  record.name = value.name;
  if (record.type === 24) record.strings = [(await reader.pascal(value.end)).name];
  else if (value.end !== reader.size) reader.warn(`HLL symbol ${record.type} has trailing bytes after its name.`);
};

export const readHllSymbols = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewSymbols> => {
  const records: LegacyCodeViewSymbol[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const length = await readHllLength(reader, offset);
      if (!length.size || length.size > reader.size - length.end) throw new Error("Invalid HLL symbol record length.");
      const source = reader.subsection(length.end, length.size);
      const record: LegacyCodeViewSymbol = { type: (await source.view(0, 1)).getUint8(0) };
      records.push(record);
      try { await readSymbol(source, record); }
      catch (error) { reader.warn(`HLL symbol ${record.type}: ${String(error)}`); }
      offset = length.end + length.size;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "symbols", encoding: "hll", records };
};
