import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewSource {
  kind: "source";
  files: { name: string; segments: { segment: number; start: number; end: number;
    lines: { offset: number; line: number }[] }[] }[];
}

// OMFSourceModule / OMFSourceFile / OMFSourceLine. NBxx source names use byte lengths.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/cvdump.cpp#L914
type SourceLines = { segment: number; lines: { offset: number; line: number }[] };

const readSourceLines = async (reader: LegacyCodeViewReader, lineOffset: number): Promise<SourceLines> => {
  const header = await reader.view(lineOffset, 4);
  const count = header.getUint16(2, true);
  if (count * 6 > reader.size - lineOffset - 4) throw new Error("CodeView source line pairs are truncated.");
  const lines: { offset: number; line: number }[] = [];
  for (let index = 0; index < count; index++) lines.push({
    offset: await reader.uint32(lineOffset + 4 + index * 4),
    line: await reader.uint16(lineOffset + 4 + count * 4 + index * 2) });
  return { segment: header.getUint16(0, true), lines };
};

const readSourceSegment = async (reader: LegacyCodeViewReader, rangeOffset: number, lines: SourceLines) => {
  const range = await reader.view(rangeOffset, 8);
  const start = range.getUint32(0, true);
  const end = range.getUint32(4, true);
  if (end < start) reader.warn("CodeView source segment range is reversed.");
  if (lines.lines.some(line => line.offset < start || line.offset > end)) {
    reader.warn("CodeView line offset lies outside its source segment range.");
  }
  return { ...lines, start, end };
};

const readSourceFile = async (reader: LegacyCodeViewReader, offset: number,
  lines: Map<number, SourceLines>) => {
  const header = await reader.view(offset, 4);
  const count = header.getUint16(0, true);
  if (count * 12 > reader.size - offset - 4) throw new Error("CodeView source file segment arrays are truncated.");
  if (header.getUint16(2, true)) reader.warn("CodeView source file reserved field is nonzero.");
  const segments: LegacyCodeViewSource["files"][number]["segments"] = [];
  for (let index = 0; index < count; index++) {
    const lineOffset = await reader.uint32(offset + 4 + index * 4);
    let source = lines.get(lineOffset);
    if (!source) { source = await readSourceLines(reader, lineOffset); lines.set(lineOffset, source); }
    segments.push(await readSourceSegment(reader, offset + 4 + count * 4 + index * 8, source));
  }
  return { name: (await reader.pascal(offset + 4 + count * 12)).name, segments };
};

export const readLegacyCodeViewSource = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewSource> => {
  const header = await reader.view(0, 4);
  const fileCount = header.getUint16(0, true);
  const segmentCount = header.getUint16(2, true);
  if (fileCount * 4 + segmentCount * 10 > reader.size - 4) {
    throw new Error("CodeView source module arrays are truncated.");
  }
  const files: LegacyCodeViewSource["files"] = [];
  const decoded = new Map<number, LegacyCodeViewSource["files"][number]>();
  const lines = new Map<number, SourceLines>();
  for (let index = 0; index < fileCount; index++) {
    const offset = await reader.uint32(4 + index * 4);
    let file = decoded.get(offset);
    if (!file) { file = await readSourceFile(reader, offset, lines); decoded.set(offset, file); }
    files.push(file);
  }
  return { kind: "source", files };
};
