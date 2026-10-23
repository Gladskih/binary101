import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewModule } from "./legacy-codeview-modules.js";
import type { LegacyCodeViewOldLines } from "./legacy-codeview-compatibility.js";

// The repeated NBxx plus backward distance is a terminal trailer, not subsection data.
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/dip/hllcv/c/hllld.c
export const readCodeViewCv3Payload = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewReader> => {
  if (reader.size < 16) return reader;
  const footer = await reader.view(reader.size - 8, 8);
  if (footer.getUint32(0, true) !== await reader.uint32(0)) return reader;
  if (footer.getUint32(4, true) !== reader.size) reader.warn("CV3 trailer backward distance does not match its payload.");
  return reader.subsection(0, reader.size - 8);
};

// Open Watcom selects cv3_module_32 for NB00 in PE (NB02 retains cv3_module_16).
// The WORD-count directory still uses packed 10-byte cv3_dir_entry records.
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/watcom/h/hll.h
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/dip/hllcv/c/hllmod.c#L133
const readSegment = async (reader: LegacyCodeViewReader, offset: number) => {
  const view = await reader.view(offset, 10);
  return { segment: view.getUint16(0, true), offset: view.getUint32(2, true), size: view.getUint32(6, true) };
};

export const readCodeViewCv3Module32 = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewModule> => {
  const header = await reader.view(0, 16);
  const name = await reader.pascal(16);
  const count = Math.max(1, header.getUint8(14));
  if (header.getUint8(15)) reader.warn("CV3 module reserved byte is nonzero.");
  if ((count - 1) * 10 > reader.size - name.end) throw new Error("CV3 module segments are truncated.");
  const segments = [await readSegment(reader, 0)];
  for (let index = 1; index < count; index++) segments.push(await readSegment(reader, name.end + (index - 1) * 10));
  return { kind: "module", name: name.name, overlay: header.getUint16(10, true), library: header.getUint16(12, true),
    style: "CV", segments };
};

// sstSrcLines (0x105) predates sstSrcLnSeg: no segment WORD, and WORD offsets
// even in Open Watcom's NB00_32BIT path. Do not invent a segment index.
// https://github.com/open-watcom/open-watcom-v2/blob/065b3083b9f06919c871c67ce608e3b29674ffce/bld/dip/hllcv/c/hllcue.c
export const readCodeViewCv3SourceLines = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewOldLines> => {
  const files: LegacyCodeViewOldLines["files"] = [];
  let offset = 0;
  while (offset < reader.size) {
    const name = await reader.pascal(offset);
    const count = await reader.uint16(name.end);
    if (count * 4 > reader.size - name.end - 2) throw new Error("CV3 source line pairs are truncated.");
    const lines: LegacyCodeViewOldLines["files"][number]["lines"] = [];
    for (let index = 0; index < count; index++) {
      const view = await reader.view(name.end + 2 + index * 4, 4);
      lines.push({ line: view.getUint16(0, true), offset: view.getUint16(2, true) });
    }
    files.push({ name: name.name, lines });
    offset = name.end + 2 + count * 4;
  }
  return { kind: "oldLines", files };
};
