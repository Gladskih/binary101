import { DwarfStringReader } from "./strings.js";
"use strict";

import { executeDwarfLineProgram } from "./line-machine.js";
import { parseDwarfLineHeader } from "./line-header.js";
import type {
  DwarfLineProgram,
  DwarfSectionSource
} from "./types.js";

export const parseDwarfLines = async (
  source: DwarfSectionSource,
  sections: Map<string, DwarfSectionSource>,
  littleEndian: boolean,
  issues: string[], strings = new DwarfStringReader(sections, littleEndian ? "little" : "big", issues)
): Promise<DwarfLineProgram[]> => {
  const programs: DwarfLineProgram[] = [];
  let offset = 0;
  while (offset < source.section.size) {
    const header = await parseDwarfLineHeader(
      source, sections, offset, littleEndian, issues, strings
    );
    if (!header) break;
    const machine = await executeDwarfLineProgram(source, header, littleEndian, issues);
    programs.push({
      offset: header.offset,
      length: header.length,
      format: header.format,
      version: header.version,
      addressSize: machine.addressSize,
      directories: header.directories,
      files: machine.files,
      rows: machine.rows
    });
    if (header.end <= offset) break;
    offset = header.end;
  }
  return programs;
};
