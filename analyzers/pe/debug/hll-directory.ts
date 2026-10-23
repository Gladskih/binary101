import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewDirectory } from "./legacy-codeview-directory.js";
import type { LegacyCodeViewModule } from "./legacy-codeview-modules.js";

export interface HllModule extends LegacyCodeViewModule { version: number; }

// IBM HLL Appendix A: 8-byte directory header, 12-byte entries, and module
// descriptors with DWORD contributions and additional segments after the name.
// https://www.os2site.com/sw/dev/openwatcom/docs/ibmhll.htm
export const readHllDirectory = async (reader: LegacyCodeViewReader,
  offset: number): Promise<LegacyCodeViewDirectory> => {
  if (offset < 8) throw new Error("HLL directory offset overlaps its header.");
  const header = await reader.view(offset, 8);
  const headerSize = header.getUint16(0, true);
  const entrySize = header.getUint16(2, true);
  const count = header.getUint32(4, true);
  if (headerSize < 8 || entrySize < 12) throw new Error("Invalid HLL directory header or entry size.");
  await reader.view(offset, headerSize);
  const available = Math.floor((reader.size - offset - headerSize) / entrySize);
  if (count > available) reader.warn("HLL directory entries extend past payload bounds.");
  const entries: LegacyCodeViewDirectory["entries"] = [];
  for (let index = 0; index < Math.min(count, available); index++) {
    const entry = await reader.view(offset + headerSize + index * entrySize, 12);
    entries.push({ type: entry.getUint16(0, true), module: entry.getUint16(2, true),
      offset: entry.getUint32(4, true), size: entry.getUint32(8, true) });
  }
  return { flags: 0, entries };
};

const readSegment = async (reader: LegacyCodeViewReader, offset: number) => {
  const view = await reader.view(offset, 10);
  return { segment: view.getUint16(0, true), offset: view.getUint32(2, true), size: view.getUint32(6, true) };
};

export const readHllModule = async (reader: LegacyCodeViewReader): Promise<HllModule> => {
  const header = await reader.view(0, 20);
  const name = await reader.pascal(20);
  const count = Math.max(1, header.getUint16(14, true));
  if ((count - 1) * 10 > reader.size - name.end) throw new Error("HLL module segments are truncated.");
  const segments = [await readSegment(reader, 0)];
  for (let index = 1; index < count; index++) segments.push(await readSegment(reader, name.end + (index - 1) * 10));
  return { kind: "module", name: name.name, overlay: header.getUint16(10, true), library: header.getUint16(12, true),
    style: String.fromCharCode(header.getUint8(16), header.getUint8(17)),
    version: header.getUint16(18, true), segments };
};
