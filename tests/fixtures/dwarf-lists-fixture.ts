import { DwarfIndexedReader } from "../../analyzers/dwarf/indexed-tables.js";
import type { DwarfAttribute, DwarfUnit } from "../../analyzers/dwarf/types.js";
import { createDwarfSectionFile } from "./dwarf-semantic-fixture.js";
import {
  concatenateBytes, encodeDwarf32Unit, encodeUint16, encodeUint8, encodeUint32, encodeUint64
} from "./dwarf-fixture-encoding.js";

export const createListUnit = (version: number, attributes: DwarfAttribute[] = []): DwarfUnit => ({
  sectionName: ".debug_info", offset: 0, length: 0n, format: 32, version, unitType: 1,
  addressSize: 8, abbreviationOffset: 0n, dies: [{ offset: 12, tag: 0x11,
    parentOffset: null, attributes }]
});

export const listAttribute = (name: number, form: number, value: bigint): DwarfAttribute => ({
  name, form, value: { kind: "unsigned", value }
});

export const createDwarfListReader = (
  contents: Array<{ name: string; bytes: number[] }>, issues: string[]
): DwarfIndexedReader => {
  const fixture = createDwarfSectionFile(contents);
  return new DwarfIndexedReader(new Map(fixture.sections.map(section => [section.name, {
    summary: section, section, reader: fixture.file, decoded: true
  }])), "little", issues);
};

// DWARF 5 7.28/7.29: header with offset entry count followed by the offset table.
export const encodeListContribution = (entries: number[], offsets: number[] = []): number[] =>
  encodeDwarf32Unit(concatenateBytes(encodeUint16(5), encodeUint8(8), encodeUint8(0),
    encodeUint32(offsets.length), offsets.flatMap(encodeUint32), entries));

export const encodeAddressContribution = (addresses: bigint[]): number[] =>
  encodeDwarf32Unit(concatenateBytes(encodeUint16(5), encodeUint8(8), encodeUint8(0),
    addresses.flatMap(encodeUint64)));
