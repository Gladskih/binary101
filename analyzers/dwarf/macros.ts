import { DwarfCursor } from "./cursor.js";
import { readDwarfMacroHeader } from "./macro-header.js";
import { readDwarfMacroEntry } from "./macro-entries.js";
import { linkDwarfMacros } from "./macro-links.js";
import { DwarfStringReader } from "./strings.js";
import type { DwarfMacroHeader, DwarfMacroUnit } from "./macro-types.js";
import type { DwarfSectionSource, DwarfUnit } from "./types.js";

const readEntries = async (cursor: DwarfCursor, header: DwarfMacroHeader,
  strings: DwarfStringReader): Promise<DwarfMacroUnit["entries"]> => {
  const entries: DwarfMacroUnit["entries"] = [];
  let includes = 0;
  while (cursor.position < cursor.end) {
    const entry = await readDwarfMacroEntry(cursor, header, strings);
    if (!entry) break;
    if (entry === "end") {
      if (includes) cursor.notice("Unterminated macro include stack");
      return entries;
    }
    if (entry.opcode === 3) includes += 1;
    if (entry.opcode === 4) {
      if (!includes) cursor.notice("Unexpected macro end_file without start_file");
      else includes -= 1;
    }
    if (entry.opcode === 10) cursor.notice("Supplementary macro import requires its external debug file");
    entries.push(entry);
  }
  cursor.notice("Macro unit has no terminating opcode");
  return entries;
};

const readSection = async (source: DwarfSectionSource, byteOrder: "little" | "big",
  strings: DwarfStringReader, issues: string[]): Promise<DwarfMacroUnit[]> => {
  const cursor = new DwarfCursor(source.reader, source.section, 0, source.section.size,
    byteOrder === "little", issues);
  const units: DwarfMacroUnit[] = [];
  while (cursor.position < cursor.end) {
    const offset = cursor.position;
    const header = await readDwarfMacroHeader(cursor, source.section.name);
    if (!header) break;
    const entries = await readEntries(cursor, header, strings);
    units.push({ sectionName: source.section.name, offset, version: header.version,
      format: header.format, lineOffset: header.lineOffset, entries });
    if (cursor.failed) break;
  }
  return units;
};

export const readDwarfMacros = async (sections: Map<string, DwarfSectionSource>, units: DwarfUnit[],
  byteOrder: "little" | "big", issues: string[],
  strings = new DwarfStringReader(sections, byteOrder, issues)): Promise<DwarfMacroUnit[]> => {
  const macros: DwarfMacroUnit[] = [];
  for (const name of [".debug_macro", ".debug_macinfo"]) {
    const source = sections.get(name);
    if (source) macros.push(...await readSection(source, byteOrder, strings, issues));
  }
  await linkDwarfMacros(macros, units, strings, issues);
  return macros;
};
