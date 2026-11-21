import { alignUpTo } from "../../binary-utils.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfDebugLinkInfo } from "./types.js";
import { openElfSectionData, type ElfSectionFormat } from "./section-data.js";

// GDB debug link: NUL-terminated filename, padding to four bytes, then CRC32 in file byte order.
// https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html
export async function parseElfDebugLink(file: File, elf: ElfSectionFormat): Promise<ElfDebugLinkInfo | null> {
  const section = elf.sections.find(item => item.name === ".gnu_debuglink" && item.size > 0n);
  if (!section) return null;
  const result: ElfDebugLinkInfo = { fileName: "", crc32: null, issues: [] };
  const source = await openElfSectionData(createFileRangeReader(file, 0, file.size), section, elf, result.issues);
  if (!source) return result;
  const cursor = new DwarfCursor(source.reader, { ...source, name: ".gnu_debuglink", compressed: false },
    0, source.size, elf.littleEndian, result.issues);
  const fileName = await cursor.cstring();
  if (fileName == null) return result;
  result.fileName = fileName;
  const offset = alignUpTo(cursor.position, 4);
  if (offset + 4 <= source.size) {
    const crc = await source.reader.read(source.offset + offset, 4);
    if (crc.byteLength === 4) result.crc32 = crc.getUint32(0, elf.littleEndian);
  }
  if (result.crc32 == null) result.issues.push(".gnu_debuglink is missing the CRC32.");
  return result;
}
