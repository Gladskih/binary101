"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  TEST_DWARF,
  concatenateBytes,
  encodeAbbreviationTable,
  encodeCString,
  encodeDie,
  encodeDwarf32Unit,
  encodeNullDie,
  encodeUint8,
  encodeUint16,
  encodeUint32
} from "./dwarf-fixture-encoding.js";
import {
  createDwarf4LineSection,
  createDwarf5LineSection,
  createDwarf5LineStrings
} from "./dwarf-line-fixture.js";

type DwarfFixture = {
  file: MockFile;
  sections: Array<{ name: string; offset: number; size: number; compressed: boolean }>;
};

const createFixture = (
  name: string,
  sectionContents: Array<{ name: string; bytes: number[] }>
): DwarfFixture => {
  let offset = 0;
  const sections = sectionContents.map(section => {
    const input = { name: section.name, offset, size: section.bytes.length, compressed: false };
    offset += section.bytes.length;
    return input;
  });
  return {
    file: new MockFile(
      Uint8Array.from(concatenateBytes(...sectionContents.map(section => section.bytes))),
      name
    ),
    sections
  };
};

const createDwarf4Abbreviations = (): number[] => encodeAbbreviationTable([
  {
    code: TEST_DWARF.abbreviationCode.compileUnit,
    tag: TEST_DWARF.tag.compileUnit,
    children: TEST_DWARF.children.yes,
    attributes: [
      { name: TEST_DWARF.attribute.producer, form: TEST_DWARF.form.stringPointer },
      { name: TEST_DWARF.attribute.language, form: TEST_DWARF.form.data2 },
      { name: TEST_DWARF.attribute.name, form: TEST_DWARF.form.string },
      { name: TEST_DWARF.attribute.statementList, form: TEST_DWARF.form.sectionOffset }
    ]
  },
  {
    code: TEST_DWARF.abbreviationCode.subprogram,
    tag: TEST_DWARF.tag.subprogram,
    children: TEST_DWARF.children.no,
    attributes: [{ name: TEST_DWARF.attribute.name, form: TEST_DWARF.form.string }]
  }
]);

const createDwarf4Info = (rootAbbreviationCode: number): number[] => encodeDwarf32Unit(
  concatenateBytes(
    encodeUint16(TEST_DWARF.version.four),
    encodeUint32(TEST_DWARF.sectionOffset.start),
    encodeUint8(TEST_DWARF.addressSize.x64),
    encodeDie(
      rootAbbreviationCode,
      encodeUint32(TEST_DWARF.sectionOffset.start),
      encodeUint16(TEST_DWARF.language.c99),
      encodeCString("main.c"),
      encodeUint32(TEST_DWARF.sectionOffset.start)
    ),
    encodeDie(TEST_DWARF.abbreviationCode.subprogram, encodeCString("main")),
    encodeNullDie()
  )
);

export const createDwarf4SectionsFixture = (
  rootAbbreviationCode: number = TEST_DWARF.abbreviationCode.compileUnit
): DwarfFixture =>
  createFixture("dwarf4.bin", [
    { name: ".debug_info", bytes: createDwarf4Info(rootAbbreviationCode) },
    { name: ".debug_abbrev", bytes: createDwarf4Abbreviations() },
    { name: ".debug_str", bytes: encodeCString("fixture compiler") },
    { name: ".debug_line", bytes: createDwarf4LineSection() }
  ]);

const createDwarf5Abbreviations = (): number[] => encodeAbbreviationTable([{
  code: TEST_DWARF.abbreviationCode.compileUnit,
  tag: TEST_DWARF.tag.compileUnit,
  children: TEST_DWARF.children.no,
  attributes: [
    {
      name: TEST_DWARF.attribute.language,
      form: TEST_DWARF.form.implicitConstant,
      implicitConstant: TEST_DWARF.language.rust
    },
    { name: TEST_DWARF.attribute.name, form: TEST_DWARF.form.string },
    { name: TEST_DWARF.attribute.statementList, form: TEST_DWARF.form.sectionOffset }
  ]
}]);

export const createDwarf5SectionsFixture = (): DwarfFixture => createFixture("dwarf5.bin", [
  {
    name: ".debug_info",
    bytes: encodeDwarf32Unit(concatenateBytes(
      encodeUint16(TEST_DWARF.version.five),
      encodeUint8(TEST_DWARF.unitType.compile),
      encodeUint8(TEST_DWARF.addressSize.x64),
      encodeUint32(TEST_DWARF.sectionOffset.start),
      encodeDie(
        TEST_DWARF.abbreviationCode.compileUnit,
        encodeCString("lib.rs"),
        encodeUint32(TEST_DWARF.sectionOffset.start)
      )
    ))
  },
  { name: ".debug_abbrev", bytes: createDwarf5Abbreviations() },
  { name: ".debug_line", bytes: createDwarf5LineSection() },
  { name: ".debug_line_str", bytes: createDwarf5LineStrings() }
]);
