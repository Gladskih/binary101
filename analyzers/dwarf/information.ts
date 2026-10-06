import { DwarfStringReader } from "./strings.js";
import { DWARF_SECTION } from "./constants.js";
import { parseAbbreviationTable } from "./abbreviations.js";
import { parseDwarfDies, resolveDwarfDieStrings } from "./dies.js";
import { parseDwarfUnitHeader, type DwarfUnitHeader } from "./unit-header.js";
import type { DwarfAbbreviation, DwarfSectionSource, DwarfUnit } from "./types.js";

class InformationReader {
  readonly #sections: Map<string, DwarfSectionSource>;
  readonly #byteOrder: "little" | "big";
  readonly #issues: string[];
  readonly #abbreviations = new Map<bigint, Map<bigint, DwarfAbbreviation> | null>();
  readonly #strings: DwarfStringReader;

  constructor(sections: Map<string, DwarfSectionSource>, byteOrder: "little" | "big", issues: string[], strings: DwarfStringReader) {
    this.#sections = sections;
    this.#byteOrder = byteOrder;
    this.#issues = issues;
    this.#strings = strings;
  }

  async #abbreviationTable(offset: bigint): Promise<Map<bigint, DwarfAbbreviation> | null> {
    const source = this.#sections.get(DWARF_SECTION.abbreviations)!;
    if (this.#abbreviations.has(offset)) return this.#abbreviations.get(offset)!;
    const parsed = await parseAbbreviationTable(source.reader, source.section, offset,
      this.#byteOrder === "little", this.#issues);
    this.#abbreviations.set(offset, parsed);
    return parsed;
  }

  async #unit(source: DwarfSectionSource, header: DwarfUnitHeader): Promise<DwarfUnit | null> {
    const abbreviations = await this.#abbreviationTable(header.abbreviationOffset);
    if (!abbreviations) return null;
    const dies = await parseDwarfDies(source.reader, source.section, header,
      abbreviations, this.#byteOrder === "little", this.#issues);
    return {
      sectionName: source.section.name, offset: header.offset, length: header.length,
      format: header.format, version: header.version, unitType: header.unitType,
      addressSize: header.addressSize, abbreviationOffset: header.abbreviationOffset,
      ...(header.typeSignature == null ? {} : { typeSignature: header.typeSignature }),
      ...(header.typeOffset == null ? {} : { typeOffset: header.typeOffset }),
      ...(header.dwoId == null ? {} : { dwoId: header.dwoId }),
      dies: await resolveDwarfDieStrings(dies, {
        version: header.version, format: header.format,
        addressSize: header.addressSize, stringOffsetsBase: null
      }, this.#strings)
    };
  }

  async read(source: DwarfSectionSource): Promise<DwarfUnit[]> {
    if (!this.#sections.has(DWARF_SECTION.abbreviations)) {
      this.#issues.push(`${source.section.name}: ${DWARF_SECTION.abbreviations} is required to decode units.`);
      return [];
    }
    const units: DwarfUnit[] = [];
    let offset = 0;
    while (offset < source.section.size) {
      const header = await parseDwarfUnitHeader(source.reader, source.section,
        offset, this.#byteOrder === "little", this.#issues);
      if (!header) break;
      const unit = await this.#unit(source, header);
      if (unit) units.push(unit);
      if (header.end <= offset) break;
      offset = header.end;
    }
    return units;
  }
}

export const readDwarfInformation = async (
  sources: DwarfSectionSource[], sections: Map<string, DwarfSectionSource>,
  byteOrder: "little" | "big", issues: string[],
  strings = new DwarfStringReader(sections, byteOrder, issues)
): Promise<DwarfUnit[]> => {
  const reader = new InformationReader(sections, byteOrder, issues, strings);
  const units: DwarfUnit[] = [];
  for (const source of sources) units.push(...await reader.read(source));
  return units;
};
