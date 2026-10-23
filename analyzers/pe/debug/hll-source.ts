import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface HllSource {
  kind: "hllSource";
  files: { index: number; name: string }[];
  groups: { file: number; segment: number; category: string; values: number[] }[];
}

type LineKind = 0 | 1 | 2 | 4;
const LINE_SIZES: Record<LineKind, number> = { 0: 8, 1: 12, 2: 16, 4: 8 };
const LINE_NAMES: Record<LineKind, string> = {
  0: "Source lines", 1: "Listing lines", 2: "Source and listing lines", 4: "Control-flow paths"
};
const isLineKind = (value: number): value is LineKind => [0, 1, 2, 4].includes(value);

// IBM HLL Line Number Table figures 64-67; earlier headers and file indices
// are publicly reversed in Open Watcom hll.h / hllcue.c (HL1/HL2/HL3).
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/watcom/h/hll.h
// hllcue.c explicitly routes HL04/HL05/HL06 through its shared source-table reader.
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/dip/hllcv/c/hllcue.c#L523
const readFiles = async (reader: LegacyCodeViewReader, result: HllSource, version: number): Promise<void> => {
  const header = await reader.view(0, 12);
  const count = header.getUint32(8, true);
  const base = version < 0x400 ? header.getUint32(0, true) : 0;
  if (count > reader.size - 12) throw new Error("HLL source file names are truncated.");
  let offset = 12;
  for (let index = 0; index < count; index++) {
    const name = await reader.pascal(offset);
    result.files.push({ index: base + index + 1, name: name.name });
    offset = name.end;
  }
  if (offset !== reader.size) reader.warn("HLL file table has trailing bytes.");
};

const readLines = async (reader: LegacyCodeViewReader, result: HllSource, segment: number,
  category: LineKind, version: number): Promise<void> => {
  const stride = LINE_SIZES[category];
  const groups = new Map<number, HllSource["groups"][number]>();
  for (let offset = 0; offset < reader.size; offset += stride) {
    const record = await reader.view(offset, stride);
    const file = sourceFileIndex(record, category, version);
    const group = groups.get(file) ?? { file, segment, category: LINE_NAMES[category], values: [] };
    group.values.push(category === 1 ? record.getUint32(0, true)
      : category === 4 ? record.getUint16(4, true) : record.getUint16(0, true));
    groups.set(file, group);
  }
  result.groups.push(...groups.values());
};

const sourceFileIndex = (record: DataView, category: number, version: number): number => {
  if (category === 1) return 0;
  if (category === 4) return record.getUint16(6, true);
  return version < 0x300 ? record.getUint8(2) : record.getUint16(2, true);
};

const readOldBlock = async (reader: LegacyCodeViewReader, result: HllSource, version: number): Promise<number> => {
  const size = version === 0x100 ? 8 : 12;
  const header = await reader.view(0, size);
  if (header.getUint8(2) !== 0) throw new Error("Unsupported early HLL line table entry type.");
  const lineSize = header.getUint16(4, true) * 8;
  const pathSize = version === 0x100 ? header.getUint16(6, true) * 6 : 0;
  const segment = version === 0x100 ? 1 : header.getUint16(6, true);
  await readLines(reader.subsection(size, lineSize), result, segment, 0, version);
  const fileOffset = size + lineSize + pathSize;
  const fileSize = version === 0x100 ? reader.size - fileOffset : header.getUint32(8, true);
  await reader.view(size + lineSize, pathSize + fileSize);
  if (pathSize) {
    const values: number[] = [];
    for (let offset = size + lineSize; offset < fileOffset; offset += 6) values.push(await reader.uint16(offset + 4));
    result.groups.push({ file: 0, segment, category: "Control-flow paths", values });
  }
  if (fileSize) await readFiles(reader.subsection(fileOffset, fileSize), result, version);
  return fileOffset + fileSize;
};

const readBlock = async (reader: LegacyCodeViewReader, result: HllSource): Promise<number> => {
  const core = await reader.view(0, 8);
  if (core.getUint16(0, true) || core.getUint8(3)) reader.warn("HLL source header reserved fields are nonzero.");
  const category = core.getUint8(2);
  const count = core.getUint16(4, true);
  if (category === 3) {
    const size = await reader.uint32(8);
    await reader.view(12, size);
    await readFiles(reader.subsection(12, size), result, 0x400);
    return 12 + size;
  }
  if (!isLineKind(category)) throw new Error(`Unknown HLL source table entry type ${category}.`);
  const stride = LINE_SIZES[category];
  const headerSize = category === 4 ? 8 : 12;
  await reader.view(0, headerSize + count * stride);
  await readLines(reader.subsection(headerSize, count * stride), result, core.getUint16(6, true), category, 0x400);
  return headerSize + count * stride;
};

export const readHllSource = async (reader: LegacyCodeViewReader, version: number): Promise<HllSource> => {
  const result: HllSource = { kind: "hllSource", files: [], groups: [] };
  if (![0x100, 0x200, 0x300, 0x400, 0x500, 0x600].includes(version)) {
    reader.warn(`Unsupported HLL source format version ${version}.`);
    return result;
  }
  let offset = 0;
  while (offset < reader.size) {
    try {
      const source = reader.subsection(offset, reader.size - offset);
      offset += version < 0x400 ? await readOldBlock(source, result, version) : await readBlock(source, result);
    } catch (error) { reader.warn(`HLL source: ${String(error)}`); break; }
  }
  const indices = new Set(result.files.map(file => file.index));
  if (result.groups.some(group => group.file !== 0 && !indices.has(group.file))) {
    reader.warn("HLL source records refer to a missing source file index.");
  }
  return result;
};
