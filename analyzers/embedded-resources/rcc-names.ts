import type { FileRangeReader } from "../file-range-reader.js";
import type { ResourceRange } from "./types.js";
import { readResource, requireResource, resourceBytes } from "./reader.js";

// Qt's stable resource hash (QString UTF-16 code units), not the randomized QHash seed.
// https://code.qt.io/cgit/qt/qtbase.git/tree/src/corelib/tools/qhash.cpp (qt_hash)
export const rccNameHash = (name: string): number => {
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) {
    hash = (hash << 4) + name.charCodeAt(index);
    hash ^= (hash & 0xf0000000) >>> 23;
    hash &= 0x0fffffff;
  }
  return hash;
};

export const readRccName = async (
  reader: FileRangeReader, range: ResourceRange, offset: number
): Promise<{ name: string; hash: number }> => {
  const header = await readResource(reader, range, offset, 6);
  const name = new TextDecoder("utf-16be", { fatal: true, ignoreBOM: true }).decode(resourceBytes(
    await readResource(reader, range, offset + 6, header.getUint16(0) * 2)));
  requireResource(name.length > 0 && !name.includes("\0") && !name.includes("/"), "Invalid RCC path component");
  const hash = header.getUint32(2);
  requireResource(hash === rccNameHash(name), "RCC name hash mismatch");
  return { name, hash };
};
