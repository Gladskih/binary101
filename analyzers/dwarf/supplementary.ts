import { DwarfCursor } from "./cursor.js";
import type { DwarfSectionSource } from "./types.js";

export type DwarfSupplementaryFile = {
  version: 5;
  isSupplementary: boolean;
  filename: string;
  checksum: Uint8Array;
};
export type DwarfAlternateFile = { filename: string; buildId: Uint8Array };

const validateFilename = (cursor: DwarfCursor, flag: number, filename: string): void => {
  if (flag === 1 && filename) cursor.notice("Supplementary file must have an empty filename");
  if (flag === 0 && !filename) cursor.notice("Main file has an empty supplementary filename");
};

// DWARF 5 7.3.6: .debug_sup identifies the external supplementary file and checksum.
// https://dwarfstd.org/doc/DWARF5.pdf
export const readDwarfSupplementaryFile = async (source: DwarfSectionSource,
  byteOrder: "little" | "big", issues: string[]): Promise<DwarfSupplementaryFile | null> => {
  const cursor = new DwarfCursor(source.reader, source.section, 0, source.section.size,
    byteOrder === "little", issues);
  const version = await cursor.uint16();
  const flag = await cursor.uint8();
  if (cursor.failed) return null;
  if (version !== 5 || (flag !== 0 && flag !== 1)) {
    cursor.fail("Invalid supplementary file version or flag");
    return null;
  }
  const filename = await cursor.cstring();
  const size = await cursor.uleb();
  const checksum = size == null ? null : await cursor.bytes(size);
  if (filename == null || checksum == null) return null;
  validateFilename(cursor, flag!, filename);
  if (cursor.position < cursor.end) cursor.notice("Trailing bytes after supplementary checksum");
  return { version: 5, isSupplementary: flag === 1, filename, checksum };
};

// GNU alternate links contain a NUL-terminated filename followed by raw build-id bytes.
// https://sourceware.org/pipermail/binutils/2013-August/082203.html
export const readDwarfAlternateFile = async (source: DwarfSectionSource,
  issues: string[]): Promise<DwarfAlternateFile | null> => {
  const cursor = new DwarfCursor(source.reader, source.section, 0, source.section.size, true, issues);
  const filename = await cursor.cstring();
  if (filename == null) return null;
  const buildId = await cursor.bytes(cursor.end - cursor.position);
  if (!buildId) return null;
  if (!filename || !buildId.length) cursor.notice("Alternate debug link has no filename or build identifier");
  return { filename, buildId };
};
