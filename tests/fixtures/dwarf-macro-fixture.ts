import { createDwarfSectionFile } from "./dwarf-semantic-fixture.js";
import { createDwarfSemanticFixture } from "./dwarf-semantic-fixture.js";
import { concatenateBytes, encodeCString, encodeUint16, encodeUint32 } from "./dwarf-fixture-encoding.js";

// DWARF 5 6.3 / Table 7.27: macros have no initial length; opcode 0 terminates a unit.
// https://dwarfstd.org/doc/DWARF5.pdf
export const createDwarfMacroFixture = () => createDwarfSectionFile([
  { name: ".debug_macro", bytes: concatenateBytes(
    encodeUint16(5), [2], encodeUint32(0), [3, 1, 1, 1, 7], encodeCString("LIMIT 42"),
    [2, 8], encodeCString("OLD"), [5, 9], encodeUint32(0), [4, 0]
  ) },
  { name: ".debug_str", bytes: encodeCString("SHARED(x) ((x) + 1)") }
]);

export const dwarfMacroSources = (contents: Array<{ name: string; bytes: number[] }>) => {
  const fixture = createDwarfSectionFile(contents);
  return new Map(fixture.sections.map(section => [section.name, {
    section, summary: section, reader: fixture.file, decoded: true
  }]));
};

export const createDwarfSemanticMacroFixture = () => {
  const semantic = createDwarfSemanticFixture();
  const macro = createDwarfMacroFixture();
  return createDwarfSectionFile([semantic, macro].flatMap(fixture => fixture.sections.map(section => ({
    name: section.name, bytes: Array.from(fixture.file.data.subarray(section.offset, section.offset + section.size))
  }))));
};
