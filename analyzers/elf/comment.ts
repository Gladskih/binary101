import { DwarfCursor } from "../dwarf/cursor.js";
import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfCommentInfo } from "./types.js";
import { openElfSectionData, type ElfSectionFormat } from "./section-data.js";

export async function parseElfComment(file: File, elf: ElfSectionFormat): Promise<ElfCommentInfo | null> {
  const section = elf.sections.find(item => item.name === ".comment" && item.size > 0n);
  if (!section) return null;
  const result: ElfCommentInfo = { strings: [], issues: [] };
  const source = await openElfSectionData(createFileRangeReader(file, 0, file.size), section, elf, result.issues);
  if (!source) return result;
  const cursor = new DwarfCursor(source.reader, { ...source, name: ".comment", compressed: false },
    0, source.size, elf.littleEndian, result.issues);
  while (cursor.position < cursor.end) {
    const text = await cursor.cstring();
    if (text == null) break;
    if (text) result.strings.push(text);
  }
  return result;
}
