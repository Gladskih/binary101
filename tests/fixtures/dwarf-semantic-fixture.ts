import { MockFile } from "../helpers/mock-file.js";
import {
  concatenateBytes, encodeAbbreviationTable, encodeCString, encodeDwarf32Unit,
  encodeSleb, encodeUint8, encodeUint16, encodeUint32, encodeUint64, encodeUleb
} from "./dwarf-fixture-encoding.js";
import { createDwarf4LineSection } from "./dwarf-line-fixture.js";

// Independent encoding oracle: DWARF 5 Tables 7.3/7.5/7.17, sections 7.5.1/7.5.3.
// https://dwarfstd.org/doc/DWARF5.pdf
export const createDwarfSectionFile = (contents: Array<{ name: string; bytes: number[] }>) => {
  let offset = 0;
  const sections = contents.map(item => {
    const section = { name: item.name, offset, size: item.bytes.length, compressed: false };
    offset += item.bytes.length;
    return section;
  });
  return { file: new MockFile(Uint8Array.from(concatenateBytes(...contents.map(item => item.bytes)))),
    sections };
};

export const createDwarfSemanticFixture = (parameterCount = 1) => {
  const root = concatenateBytes(encodeUleb(1), encodeCString("main.c"),
    encodeCString("/project"), encodeUint32(0));
  // A DWARF32 v4 compilation-unit header occupies 11 bytes (7.5.1.1).
  const typeOffset = 11 + root.length;
  const baseType = concatenateBytes(encodeUleb(2), encodeCString("int"), encodeUint8(4));
  const functionOffset = typeOffset + baseType.length;
  const subprogram = concatenateBytes(encodeUleb(3), encodeCString("calculate"),
    encodeUint32(typeOffset), encodeUint64(0x1000), encodeUint32(6), encodeUleb(1), encodeUleb(7));
  const parameters = Array.from({ length: parameterCount }, (_, index) => concatenateBytes(
    encodeUleb(4), encodeCString(index ? "input" + index : "input"),
    encodeUint32(typeOffset), encodeUleb(2), encodeUint8(0x91), encodeSleb(-8)
  )).flat();
  return { typeOffset, functionOffset, ...createDwarfSectionFile([
    { name: ".debug_info", bytes: encodeDwarf32Unit(concatenateBytes(
      encodeUint16(4), encodeUint32(0), encodeUint8(8), root, baseType, subprogram,
      parameters, encodeUleb(0), encodeUleb(0)
    )) },
    { name: ".debug_abbrev", bytes: encodeAbbreviationTable([
      { code: 1, tag: 0x11, children: 1, attributes: [
        { name: 0x03, form: 0x08 }, { name: 0x1b, form: 0x08 }, { name: 0x10, form: 0x17 }
      ] },
      { code: 2, tag: 0x24, children: 0, attributes: [
        { name: 0x03, form: 0x08 }, { name: 0x0b, form: 0x0b }
      ] },
      { code: 3, tag: 0x2e, children: 1, attributes: [
        { name: 0x03, form: 0x08 }, { name: 0x49, form: 0x13 },
        { name: 0x11, form: 0x01 }, { name: 0x12, form: 0x06 },
        { name: 0x3a, form: 0x0f }, { name: 0x3b, form: 0x0f }
      ] },
      { code: 4, tag: 0x05, children: 0, attributes: [
        { name: 0x03, form: 0x08 }, { name: 0x49, form: 0x13 }, { name: 0x02, form: 0x18 }
      ] }
    ]) },
    { name: ".debug_line", bytes: createDwarf4LineSection() }
  ]) };
};
