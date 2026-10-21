import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface Td32Source {
  kind: "source";
  files: { nameIndex: number; segments: { segment: number; start: number; end: number;
    lines: { offset: number; line: number }[] }[] }[];
}
type SourceLines = { segment: number; lines: { offset: number; line: number }[] };

// TSourceModuleInfo/TSourceFileEntry/TLineMappingEntry: the file name index is
// an unaligned DWORD at +2, so the file's fixed header is six bytes, not CV4's four.
// https://github.com/project-jedi/jcl/blob/10b92737050d9aaa0af17fe099a737d390b6c80e/jcl/source/windows/JclTD32.pas#L263
const readLines = async (reader: LegacyCodeViewReader, offset: number): Promise<SourceLines> => {
  const header = await reader.view(offset, 4);
  const count = header.getUint16(2, true);
  if (count * 6 > reader.size - offset - 4) throw new Error("TD32 line pairs are truncated.");
  const lines: SourceLines["lines"] = [];
  for (let index = 0; index < count; index++) lines.push({
    offset: await reader.uint32(offset + 4 + index * 4),
    line: await reader.uint16(offset + 4 + count * 4 + index * 2) });
  return { segment: header.getUint16(0, true), lines };
};

const readFile = async (reader: LegacyCodeViewReader, offset: number, cache: Map<number, SourceLines>) => {
  const header = await reader.view(offset, 6);
  const count = header.getUint16(0, true);
  if (count * 12 > reader.size - offset - 6) throw new Error("TD32 source file arrays are truncated.");
  const segments: Td32Source["files"][number]["segments"] = [];
  for (let index = 0; index < count; index++) {
    const lineOffset = await reader.uint32(offset + 6 + index * 4);
    let source = cache.get(lineOffset);
    if (!source) { source = await readLines(reader, lineOffset); cache.set(lineOffset, source); }
    const range = await reader.view(offset + 6 + count * 4 + index * 8, 8);
    const start = range.getUint32(0, true);
    const end = range.getUint32(4, true);
    if (end < start) reader.warn("TD32 source range is reversed.");
    if (source.lines.some(line => line.offset < start || line.offset > end)) reader.warn("TD32 line lies outside its source range.");
    segments.push({ ...source, start, end });
  }
  return { nameIndex: header.getUint32(2, true), segments };
};

export const readTd32Source = async (reader: LegacyCodeViewReader): Promise<Td32Source> => {
  const header = await reader.view(0, 4);
  const count = header.getUint16(0, true);
  if (count * 4 + header.getUint16(2, true) * 10 > reader.size - 4) {
    throw new Error("TD32 source module arrays are truncated.");
  }
  const files: Td32Source["files"] = [];
  const decoded = new Map<number, Td32Source["files"][number]>();
  const lines = new Map<number, SourceLines>();
  for (let index = 0; index < count; index++) {
    const offset = await reader.uint32(4 + index * 4);
    let file = decoded.get(offset);
    if (!file) { file = await readFile(reader, offset, lines); decoded.set(offset, file); }
    files.push(file);
  }
  return { kind: "source", files };
};
