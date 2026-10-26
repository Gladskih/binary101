import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewSymbolName } from "./legacy-codeview-symbol-names.js";
import { readLegacyCodeViewConstantSymbol, type LegacyCodeViewConstant } from "./legacy-codeview-constant-symbols.js";
import { readLegacyCodeViewProcedureSymbol, type LegacyCodeViewProcedure } from "./legacy-codeview-procedure-symbols.js";
import { readLegacyCodeViewDataSymbol, type LegacyCodeViewDataSymbol } from "./legacy-codeview-data-symbols.js";
import { readCodeViewFrame } from "./codeview-frame-symbol.js";
import { readCodeViewLocal } from "./codeview-local-symbols.js";
import { readCodeViewLocalRange } from "./codeview-local-ranges.js";
import type { CodeViewFrame, CodeViewLocalVariable, CodeViewLocalRange } from "./codeview-local-types.js";

export interface LegacyCodeViewSymbolText {
  name?: string;
  strings?: string[];
  constant?: LegacyCodeViewConstant;
  procedure?: LegacyCodeViewProcedure;
  data?: LegacyCodeViewDataSymbol;
  frame?: CodeViewFrame;
  local?: CodeViewLocalVariable;
  localRange?: CodeViewLocalRange;
}
type ReadCodeViewString = (offset: number) => Promise<{ name: string; end: number }>;

const readLocalMetadata = async (reader: LegacyCodeViewReader,
  type: number): Promise<LegacyCodeViewSymbolText | null> => {
  try {
    return await readCodeViewFrame(reader, type) ?? await readCodeViewLocal(reader, type)
      ?? await readCodeViewLocalRange(reader, type);
  } catch (error) { reader.warn(`CodeView local/frame metadata: ${String(error)}`); return {}; }
};

const readSymbolMetadata = async (reader: LegacyCodeViewReader,
  type: number): Promise<LegacyCodeViewSymbolText | null> =>
  await readLegacyCodeViewConstantSymbol(reader, type) ?? await readLegacyCodeViewProcedureSymbol(reader, type)
    ?? await readLegacyCodeViewDataSymbol(reader, type) ?? await readLocalMetadata(reader, type);

const readCountedStrings = async (reader: LegacyCodeViewReader, start: number,
  count: number, readName: ReadCodeViewString): Promise<string[]> => {
  const strings: string[] = [];
  let offset = start;
  for (let index = 0; index < count; index++) {
    try {
      const value = await readName(offset);
      strings.push(value.name);
      offset = value.end;
    } catch (error) { reader.warn(`CodeView symbol string: ${String(error)}`); break; }
  }
  return strings;
};

const readTerminatedStrings = async (reader: LegacyCodeViewReader, start: number,
  readName: ReadCodeViewString): Promise<string[]> => {
  const strings: string[] = [];
  let offset = start;
  while (offset < reader.size) {
    try {
      const value = await readName(offset);
      // C7Compile2/C7Envblock consume key/value pairs: an empty value is
      // meaningful; only an empty key terminates the command block.
      // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym7.cpp#L5849
      if (value.name === "" && strings.length % 2 === 0) return strings;
      strings.push(value.name);
      offset = value.end;
    } catch (error) { reader.warn(`CodeView symbol string: ${String(error)}`); return strings; }
  }
  reader.warn("CodeView symbol string block has no final empty-string terminator.");
  return strings;
};

// COMPILESYM's version is followed by an optional stringZ block. Its SZ
// variant uses UTF-8; the ST variant retains its unspecified ANSI code page.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3313
const readCompilerText = async (reader: LegacyCodeViewReader, type: number): Promise<LegacyCodeViewSymbolText> => {
  await reader.view(0, 22);
  const version = type === 0x1013 ? await reader.pascal(22) : await reader.utf8Name(22);
  return { name: version.name, ...(version.end < reader.size ? {
    strings: await readTerminatedStrings(reader, version.end,
      type === 0x1013 ? reader.ansi.bind(reader) : reader.utf8Name.bind(reader))
  } : {}) };
};

/** Preserve stored text without resolving external PDBs, tokens or type references. */
export const readLegacyCodeViewSymbolText = async (
  reader: LegacyCodeViewReader, type: number
): Promise<LegacyCodeViewSymbolText> => {
  const metadata = await readSymbolMetadata(reader, type);
  if (metadata) return metadata;
  if (type === 0x1013 || type === 0x1116) return readCompilerText(reader, type);
  // ANNOTATIONSYM has a WORD count; PDBMAP has exactly two UTF-16 paths.
  // ENVBLOCKSYM is one flags byte followed by a stringZ-vectorZ.
  // Same cvinfo.h source as above, plus LLVM's SymbolRecordMapping.cpp.
  if (type === 0x1019) return { strings: await readCountedStrings(reader, 12,
    await reader.uint16(10), reader.utf8Name.bind(reader)) };
  if (type === 0x1161) return { strings: await readCountedStrings(reader, 4, 2, reader.utf16Name.bind(reader)) };
  if (type === 0x113d) {
    // cvinfo.h reserves the upper seven bits; cvdump names bit0 edit-and-continue.
    if (((await reader.view(4, 1)).getUint8(0) & 0xfe) !== 0) {
      reader.warn("CodeView environment flags set reserved bits.");
    }
    return { strings: await readTerminatedStrings(reader, 5, reader.utf8Name.bind(reader)) };
  }
  const name = await readLegacyCodeViewSymbolName(reader, type);
  return name == null ? {} : { name };
};
