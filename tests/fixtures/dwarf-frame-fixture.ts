import { concatenateBytes, encodeDwarf32Unit, encodeUint32 } from "./dwarf-fixture-encoding.js";
import { createDwarfSemanticFixture, createDwarfSectionFile } from "./dwarf-semantic-fixture.js";

// DWARF 5 6.4.1: a version-4 CIE followed by an FDE; records align to address size.
export const createDwarfFrameBytes = (): number[] => concatenateBytes(
  encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff),
    [4, 0, 4, 0, 1, 0x7c, 8, 0x0c, 4, 4, 0x88, 1])),
  encodeDwarf32Unit(concatenateBytes(encodeUint32(0), encodeUint32(4096), encodeUint32(16),
    [0x44, 0x0e, 8, 0]))
);

export const createDwarfFrameFixture = () => {
  const fixture = createDwarfSemanticFixture();
  return createDwarfSectionFile([...fixture.sections.map(section => ({ name: section.name,
    bytes: Array.from(fixture.file.data.subarray(section.offset, section.offset + section.size)) })),
  { name: ".debug_frame", bytes: createDwarfFrameBytes() }]);
};
