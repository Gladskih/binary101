import { DwarfCursor } from "./cursor.js";
import { readDwarfInitialLength } from "./initial-length.js";
import type { DwarfSectionSource } from "./types.js";

// Bounded length-prefixed sections share DWARF 5 7.4's initial-length encoding.
export async function* dwarfSectionContributions(source: DwarfSectionSource,
  byteOrder: "little" | "big", issues: string[]): AsyncGenerator<{
    offset: number; format: 32 | 64; cursor: DwarfCursor
  }> {
  const cursor = new DwarfCursor(source.reader, source.section, 0, source.section.size,
    byteOrder === "little", issues);
  while (cursor.position < cursor.end) {
    const offset = cursor.position;
    const length = await readDwarfInitialLength(cursor);
    if (!length) return;
    if (!length.length) continue;
    yield { offset, format: length.format,
      cursor: new DwarfCursor(source.reader, source.section, cursor.position, length.end,
        byteOrder === "little", issues) };
    cursor.position = length.end;
  }
}
