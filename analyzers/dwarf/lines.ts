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
  issues: string[]
): Promise<DwarfLineProgram[]> => {
  const programs: DwarfLineProgram[] = [];
  let offset = 0;
  while (offset < source.section.size) {
    const header = await parseDwarfLineHeader(
      source, sections, offset, littleEndian, issues
    );
    if (!header) break;
    const machine = await executeDwarfLineProgram(source, header, littleEndian, issues);
    programs.push({
      offset: header.offset,
      length: header.length,
      format: header.format,
      version: header.version,
      addressSize: machine.addressSize,
      directoryCount: header.directoryCount,
      fileCount: machine.fileCount,
      files: machine.files,
      rowCount: machine.rowCount,
      sequenceCount: machine.sequenceCount,
      minimumAddress: machine.minimumAddress,
      maximumAddress: machine.maximumAddress
    });
    if (header.end <= offset) break;
    offset = header.end;
  }
  return programs;
};
