import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface Td32Symbols {
  kind: "symbols";
  records: { type: number; nameIndex?: number; compiler?: string }[];
}

// Offsets include the length/type prefix; TD32's padding and DWORD name indices
// differ from NBxx symbol bodies even where the symbol kind numbers coincide.
// https://github.com/project-jedi/jcl/blob/10b92737050d9aaa0af17fe099a737d390b6c80e/jcl/source/windows/JclTD32.pas#L414
// Register/BP-relative records: unchanged tds2pdb Program.cs, SymRegister / SymbolType.BPRel32.
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const NAME_OFFSETS: Readonly<Partial<Record<number, number>>> = {
  2: 10, 3: 8, 4: 10, 9: 8, 0x200: 12,
  0x201: 16, 0x202: 16, 0x203: 16, 0x204: 40, 0x205: 40, 0x208: 24, 0x209: 12
};

const readSymbol = async (reader: LegacyCodeViewReader, type: number) => {
  const record: Td32Symbols["records"][number] = { type };
  try {
    const offset = NAME_OFFSETS[type];
    if (offset !== undefined) record.nameIndex = await reader.uint32(offset);
    if (type === 1) record.compiler = (await reader.pascal(8)).name;
  } catch (error) { reader.warn(`TD32 symbol ${type}: ${String(error)}`); }
  return record;
};

const readSymbols = async (reader: LegacyCodeViewReader, start: number, end: number): Promise<Td32Symbols> => {
  const records: Td32Symbols["records"] = [];
  for (let offset = start; offset < end;) {
    if (end - offset < 4) { reader.warn("TD32 symbol header is truncated."); break; }
    const header = await reader.view(offset, 4);
    const size = header.getUint16(0, true) + 2;
    if (size < 4 || size > end - offset) { reader.warn("TD32 symbol length exceeds its stream bounds."); break; }
    records.push(await readSymbol(reader.subsection(offset, size), header.getUint16(2, true)));
    offset += size;
  }
  return { kind: "symbols", records };
};

export const readTd32ModuleSymbols = async (reader: LegacyCodeViewReader): Promise<Td32Symbols> => {
  await reader.view(0, 4); // The module stream starts with a DWORD signature (JCL TSymbolInfos).
  return readSymbols(reader, 4, reader.size);
};

export const readTd32GlobalSymbols = async (reader: LegacyCodeViewReader): Promise<Td32Symbols> => {
  // tds2pdb's GlobalSymHeader: 16-byte hash header plus four DWORD category counts.
  const header = await reader.view(0, 32);
  const size = header.getUint32(4, true);
  const hashSize = header.getUint32(8, true) + header.getUint32(12, true);
  if (size + hashSize > reader.size - 32) reader.warn("TD32 global symbol or hash streams are truncated.");
  return readSymbols(reader, 32, Math.min(reader.size, 32 + size));
};
