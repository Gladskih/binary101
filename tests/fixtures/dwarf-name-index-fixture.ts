import { createDwarfSemanticFixture, createDwarfSectionFile } from "./dwarf-semantic-fixture.js";
import { concatenateBytes, encodeCString, encodeDwarf32Unit, encodeUint16, encodeUint32 } from "./dwarf-fixture-encoding.js";

// DWARF 5 6.1.1.4: header, unit lists, optional hashes, name/entry offsets, abbreviations, entry pool.
export const encodeDwarfNameIndex = (abbreviations: number[], entries: number[], entryOffsets = [0],
  buckets: number[] = [], hashes: number[] = []): number[] => encodeDwarf32Unit(concatenateBytes(
  encodeUint16(5), encodeUint16(0),
  [1, 0, 0, buckets.length, entryOffsets.length, abbreviations.length, 0].flatMap(encodeUint32),
  encodeUint32(0), buckets.flatMap(encodeUint32), hashes.flatMap(encodeUint32),
  entryOffsets.map(() => 0).flatMap(encodeUint32), entryOffsets.flatMap(encodeUint32), abbreviations, entries
));

export const createDwarfNameIndexFixture = () => {
  const dwarf = createDwarfSemanticFixture();
  const contents = dwarf.sections.map(section => ({ name: section.name,
    bytes: Array.from(dwarf.file.data.subarray(section.offset, section.offset + section.size)) }));
  return createDwarfSectionFile([...contents,
    { name: ".debug_str", bytes: encodeCString("calculate") },
    { name: ".debug_names", bytes: encodeDwarfNameIndex([1, 0x2e, 3, 0x13, 4, 0x19, 0, 0, 0],
      concatenateBytes([1], encodeUint32(dwarf.functionOffset), [0])) }
  ]);
};
