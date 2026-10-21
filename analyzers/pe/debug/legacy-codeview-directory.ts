import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewSubsection { type: number; module: number; offset: number; size: number; }
export interface LegacyCodeViewDirectory { flags: number; entries: LegacyCodeViewSubsection[]; }

const addDirectoryRange = (ranges: [number, number][], start: number, end: number): void => {
  let low = 0;
  let high = ranges.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (ranges[middle]![0] < start) low = middle + 1;
    else high = middle;
  }
  if ((low > 0 && ranges[low - 1]![1] > start) || (low < ranges.length && end > ranges[low]![0])) {
    throw new Error("CodeView directory ranges overlap.");
  }
  ranges.splice(low, 0, [start, end]);
};

// OMFDirHeader/OMFDirEntry, shared by NB05/06/07/08/09/11.
// https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/cv4.h
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/cvdump.cpp#L271
export const readLegacyCodeViewDirectories = async (
  reader: LegacyCodeViewReader, firstOffset: number
): Promise<LegacyCodeViewDirectory[]> => {
  const directories: LegacyCodeViewDirectory[] = [];
  const visited = new Set<number>();
  const ranges: [number, number][] = [];
  let offset = firstOffset;
  while (offset) {
    if (visited.has(offset)) { reader.warn("CodeView directory chain contains a cycle."); break; }
    visited.add(offset);
    try {
      const header = await reader.view(offset, 16);
      const headerSize = header.getUint16(0, true);
      const entrySize = header.getUint16(2, true);
      const count = header.getUint32(4, true);
      if (headerSize < 16 || entrySize < 12) throw new Error("Invalid CodeView directory header or entry size.");
      await reader.view(offset, headerSize);
      const available = Math.max(0, Math.floor((reader.size - offset - headerSize) / entrySize));
      addDirectoryRange(ranges, offset, offset + headerSize + Math.min(count, available) * entrySize);
      const directory: LegacyCodeViewDirectory = { flags: header.getUint32(12, true), entries: [] };
      directories.push(directory);
      if (count > available) reader.warn("CodeView directory entries extend past payload bounds.");
      for (let index = 0; index < Math.min(count, available); index++) {
        const view = await reader.view(offset + headerSize + index * entrySize, 12);
        directory.entries.push({ type: view.getUint16(0, true), module: view.getUint16(2, true),
          offset: view.getUint32(4, true), size: view.getUint32(8, true) });
      }
      offset = header.getUint32(8, true);
    } catch (error) { reader.warn(String(error)); break; }
  }
  if (!firstOffset) reader.warn("CodeView directory offset is zero.");
  return directories;
};
