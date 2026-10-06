import { DwarfCursor } from "../../analyzers/dwarf/cursor.js";
import { parseDwarfLineHeader } from "../../analyzers/dwarf/line-header.js";
import { createDwarfLineRegisters } from "../../analyzers/dwarf/line-registers.js";
import type { DwarfLineRow } from "../../analyzers/dwarf/types.js";
import { createDwarf4LineSection } from "./dwarf-line-fixture.js";
import { createDwarfSectionFile } from "./dwarf-semantic-fixture.js";

export const createDwarfLineMachine = async (operands: number[] = []) => {
  const fixture = createDwarfSectionFile([
    { name: ".debug_line", bytes: createDwarf4LineSection() },
    { name: "operands", bytes: operands }
  ]);
  const issues: string[] = [];
  const sections = new Map(fixture.sections.map(section => [section.name, {
    section, summary: section, reader: fixture.file, decoded: true
  }]));
  const header = (await parseDwarfLineHeader(sections.get(".debug_line")!, sections, 0, true, issues))!;
  const cursor = new DwarfCursor(fixture.file, fixture.sections[1]!, 0, operands.length, true, issues);
  const rows: DwarfLineRow[] = [];
  return { cursor, header, state: createDwarfLineRegisters(header), rows, issues };
};
