"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_SECTION } from "./constants.js";
import { DwarfIndexedReader } from "./indexed-tables.js";
import { DwarfCursor } from "./cursor.js";
import type {
  DwarfFormValue,
  DwarfSectionInput,
  DwarfSectionSource,
  DwarfUnitContext
} from "./types.js";

const findSection = (
  sections: Map<string, DwarfSectionSource>,
  name: string,
  issues: string[]
): DwarfSectionSource | null => {
  const source = sections.get(name);
  if (!source) issues.push(`${name}: section is required to resolve a DWARF string.`);
  return source ?? null;
};

const safeSectionOffset = (
  value: bigint,
  section: DwarfSectionInput,
  issues: string[]
): number | null => {
  const offset = Number(value);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= section.size) {
    issues.push(`${section.name}: string offset ${value.toString()} falls outside the section.`);
    return null;
  }
  return offset;
};

const readStringAt = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  offsetValue: bigint,
  littleEndian: boolean,
  issues: string[]
): Promise<string | null> => {
  const offset = safeSectionOffset(offsetValue, section, issues);
  if (offset == null) return null;
  return new DwarfCursor(
    reader,
    section,
    offset,
    section.size,
    littleEndian,
    issues
  ).cstring();
};

export class DwarfStringReader {
  readonly #sections: Map<string, DwarfSectionSource>;
  readonly #byteOrder: "little" | "big";
  readonly #issues: string[];
  readonly #indexed: DwarfIndexedReader;
  readonly #strings = new Map<string, Promise<string | null>>();

  constructor(sections: Map<string, DwarfSectionSource>, byteOrder: "little" | "big", issues: string[]) {
    this.#sections = sections;
    this.#byteOrder = byteOrder;
    this.#issues = issues;
    this.#indexed = new DwarfIndexedReader(sections, byteOrder, issues);
  }

  #read(name: string, offset: bigint): Promise<string | null> {
    const key = `${name}:${offset}`;
    if (!this.#strings.has(key)) {
      const source = findSection(this.#sections, name, this.#issues);
      this.#strings.set(key, source
        ? readStringAt(source.reader, source.section, offset, this.#byteOrder === "little", this.#issues)
        : Promise.resolve(null));
    }
    return this.#strings.get(key)!;
  }

  async resolve(value: DwarfFormValue | undefined, context: DwarfUnitContext): Promise<string | null> {
    if (!value) return null;
    if (value.kind === "string") return value.value;
    if (value.kind === "string-offset") return this.#read(value.sectionName, value.value);
    if (value.kind !== "string-index") return null;
    const offset = await this.#indexed.stringOffset(context, value.value);
    return offset == null ? null : this.#read(DWARF_SECTION.strings, offset);
  }
}

export const resolveDwarfString = async (
  sections: Map<string, DwarfSectionSource>,
  value: DwarfFormValue | undefined,
  context: DwarfUnitContext,
  littleEndian: boolean,
  issues: string[]
): Promise<string | null> =>
  new DwarfStringReader(sections, littleEndian ? "little" : "big", issues).resolve(value, context);
