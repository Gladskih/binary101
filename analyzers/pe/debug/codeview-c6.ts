import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewDirectory } from "./legacy-codeview-directory.js";
import type { LegacyCodeViewModule } from "./legacy-codeview-modules.js";
import { readLegacyCodeViewLibraries } from "./legacy-codeview-modules.js";
import { readLegacyCodeViewPublics, readLegacyCodeViewOldLines } from "./legacy-codeview-compatibility.js";
import { readCodeViewC6Symbols } from "./codeview-c6-symbols.js";
import { readCodeViewC6Types } from "./codeview-c6-type-records.js";
import { readCodeViewCv3SourceLines } from "./codeview-cv3.js";

// NB02 uses a WORD count and packed 10-byte directory entries (WORD size).
// Module SegInfo is 16-bit even in Microsoft's PE path; cSeg=0 means one segment.
// Additional segment descriptors follow the counted module name.
// Microsoft C Developer's Toolkit, 3.4, 3.6, 3.7; cvdump.cpp ReadNB02/GetSSTMOD.
// https://www.pcjs.org/documents/books/mspl13/c/ctoolkit/
// https://github.com/open-watcom/open-watcom-v2/blob/86df376ccbcba83a210a9bd21dff0a5f7945b5be/bld/watcom/h/hll.h
export const readCodeViewC6Directories = async (
  reader: LegacyCodeViewReader, offset: number
): Promise<LegacyCodeViewDirectory[]> => {
  if (!offset) { reader.warn("C6 CodeView directory offset is zero."); return []; }
  if (offset < 8) throw new Error("CV3 directory overlaps its signature header.");
  const count = await reader.uint16(offset);
  const available = Math.floor((reader.size - offset - 2) / 10);
  if (count > available) reader.warn("C6 CodeView directory entries extend past payload bounds.");
  const entries: LegacyCodeViewDirectory["entries"] = [];
  for (let index = 0; index < Math.min(count, available); index++) {
    const view = await reader.view(offset + 2 + index * 10, 10);
    entries.push({ type: view.getUint16(0, true), module: view.getUint16(2, true),
      offset: view.getUint32(4, true), size: view.getUint16(8, true) });
  }
  return [{ flags: 0, entries }];
};

const readSegment = async (reader: LegacyCodeViewReader, offset: number) => {
  const view = await reader.view(offset, 6);
  return { segment: view.getUint16(0, true), offset: view.getUint16(2, true), size: view.getUint16(4, true) };
};

export const readCodeViewC6Module = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewModule> => {
  const header = await reader.view(0, 12);
  const name = await reader.pascal(12);
  const count = Math.max(1, header.getUint8(10));
  if (header.getUint8(11)) reader.warn("C6 module reserved byte is nonzero.");
  if ((count - 1) * 6 > reader.size - name.end) throw new Error("C6 module segment array is truncated.");
  const segments = [await readSegment(reader, 0)];
  for (let index = 1; index < count; index++) segments.push(await readSegment(reader, name.end + (index - 1) * 6));
  return { kind: "module", name: name.name, overlay: header.getUint16(6, true), library: header.getUint16(8, true),
    style: "CV", segments };
};

export const CODEVIEW_C6_DECODERS = {
  0x101: readCodeViewC6Module, 0x102: readLegacyCodeViewPublics,
  0x103: readCodeViewC6Types, 0x104: readCodeViewC6Symbols, 0x105: readCodeViewCv3SourceLines,
  0x106: readLegacyCodeViewLibraries,
  0x108: readCodeViewC6Types, 0x109: readLegacyCodeViewOldLines
};
