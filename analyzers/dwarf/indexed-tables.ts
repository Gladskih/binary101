import { DwarfCursor } from "./cursor.js";
import { dwarfAttributeValue, dwarfNumericValue } from "./attribute-values.js";
import { readDwarfInitialLength } from "./initial-length.js";
import { DWARF_ATTRIBUTE, DWARF_FORM } from "./constants.js";
import type { DwarfAttribute, DwarfSectionSource, DwarfUnit, DwarfUnitContext } from "./types.js";

type Contribution = {
  offset: number;
  end: number;
  entriesOffset: number;
  format: 32 | 64;
  addressSize: number;
  offsetCount: number;
};

// DWARF 5 sections 7.27-7.29: contribution headers and offset-table-relative indices.
// https://dwarfstd.org/doc/DWARF5.pdf
const readContribution = async (
  source: DwarfSectionSource, offset: number, byteOrder: "little" | "big", issues: string[]
): Promise<Contribution | null> => {
  const lengthCursor = new DwarfCursor(source.reader, source.section, offset,
    source.section.size, byteOrder === "little", issues);
  const initial = await readDwarfInitialLength(lengthCursor);
  if (!initial || initial.length === 0n) return null;
  if (initial.length > BigInt(lengthCursor.end - lengthCursor.position)) return null;
  const { format, end } = initial;
  const cursor = new DwarfCursor(source.reader, source.section, lengthCursor.position,
    end, byteOrder === "little", issues);
  const encoding = await readContributionEncoding(cursor, source.section.name);
  if (!encoding) return null;
  const offsetCount = source.section.name === ".debug_addr" || source.section.name === ".debug_str_offsets"
    ? 0 : await cursor.uint32();
  if (offsetCount == null || offsetCount > (cursor.end - cursor.position) / (format / 8)) {
    cursor.fail("Indexed offset table extends beyond its contribution");
    return null;
  }
  return { offset, end, entriesOffset: cursor.position, format, ...encoding, offsetCount };
};

const readStringOffsetsHeader = async (
  cursor: DwarfCursor, version: number
): Promise<{ addressSize: number } | null> => {
  const padding = await cursor.uint16();
  if (padding == null) return null;
  if (version !== 5 || padding !== 0) { cursor.fail("Invalid string offsets header"); return null; }
  return { addressSize: 0 };
};

const readContributionEncoding = async (cursor: DwarfCursor, name: string): Promise<{ addressSize: number } | null> => {
  const version = await cursor.uint16();
  if (version == null) return null;
  if (name === ".debug_str_offsets") return readStringOffsetsHeader(cursor, version);
  const addressSize = await cursor.uint8();
  const selectorSize = await cursor.uint8();
  if (addressSize == null || selectorSize == null) return null;
  return validIndexedHeader(cursor, version, addressSize, selectorSize) ? { addressSize } : null;
};

const validIndexedHeader = (
  cursor: DwarfCursor, version: number, addressSize: number, selectorSize: number
): boolean => {
  if (version === 5 && addressSize > 0 && selectorSize === 0) return true;
  cursor.fail(selectorSize ? "Segmented indexed addresses are unsupported" : "Invalid indexed table header");
  return false;
};

const validStringOffset = (table: Contribution, offset: bigint): boolean =>
  offset + BigInt(table.format / 8) <= BigInt(table.end);

export class DwarfIndexedReader {
  readonly #sections: Map<string, DwarfSectionSource>;
  readonly #byteOrder: "little" | "big";
  readonly #issues: string[];
  readonly #skeletons: DwarfUnit[];
  readonly #contributions = new Map<string, Promise<Contribution[]>>();
  readonly #addresses = new Map<string, Promise<bigint | null>>();
  readonly #stringOffsets = new Map<string, Promise<bigint | null>>();

  constructor(sections: Map<string, DwarfSectionSource>, byteOrder: "little" | "big",
    issues: string[], skeletons: DwarfUnit[] = []) {
    this.#sections = sections;
    this.#byteOrder = byteOrder;
    this.#issues = issues;
    this.#skeletons = skeletons;
  }

  cursor(name: string, offset: bigint, end?: number): DwarfCursor | null {
    const source = this.#sections.get(name);
    if (!source || offset < 0n || offset >= BigInt(source.section.size)) {
      this.#issues.push(`${name}: missing section or offset ${offset} outside the section.`);
      return null;
    }
    return new DwarfCursor(source.reader, source.section, Number(offset),
      end ?? source.section.size, this.#byteOrder === "little", this.#issues);
  }

  address(unit: DwarfUnit, index: bigint): Promise<bigint | null> {
    const owner = this.skeleton(unit) ?? unit;
    const base = dwarfNumericValue(dwarfAttributeValue(owner.dies[0], DWARF_ATTRIBUTE.addressBase)) ??
      dwarfNumericValue(dwarfAttributeValue(owner.dies[0], 0x2133)); // DW_AT_GNU_addr_base.
    const key = `${unit.version}:${unit.addressSize}:${base}:${index}`;
    if (!this.#addresses.has(key)) this.#addresses.set(key, this.#readAddress(unit, index, base));
    return this.#addresses.get(key)!;
  }

  skeleton(unit: DwarfUnit): DwarfUnit | null {
    if (!unit.sectionName.endsWith(".dwo")) return null;
    const id = unit.dwoId ?? dwarfNumericValue(dwarfAttributeValue(unit.dies[0], 0x2131));
    if (id == null) return null;
    return this.#skeletons.find(candidate => !candidate.sectionName.endsWith(".dwo") &&
      (candidate.dwoId ?? dwarfNumericValue(dwarfAttributeValue(candidate.dies[0], 0x2131))) === id) ?? null;
  }

  baseAddress(unit: DwarfUnit): bigint | null {
    const owner = this.skeleton(unit) ?? unit;
    return dwarfNumericValue(dwarfAttributeValue(owner.dies[0], DWARF_ATTRIBUTE.lowPc)) ??
      (unit.sectionName.endsWith(".dwo") && owner === unit ? null : 0n);
  }

  async splitStringOffsetsBase(version: number): Promise<bigint | null> {
    // DWO contributions have implicit bases: LLVM DWARFUnit.cpp, determineStringOffsetsTableContribution.
    if (version < 5) return 0n;
    return BigInt((await this.#tables(".debug_str_offsets"))[0]?.entriesOffset ?? -1);
  }

  stringOffset(context: DwarfUnitContext, index: bigint): Promise<bigint | null> {
    const key = `${context.version}:${context.format}:${context.stringOffsetsBase}:${index}`;
    if (!this.#stringOffsets.has(key)) this.#stringOffsets.set(key, this.#readStringOffset(context, index));
    return this.#stringOffsets.get(key)!;
  }

  async #readStringOffset(context: DwarfUnitContext, index: bigint): Promise<bigint | null> {
    const base = context.stringOffsetsBase;
    if (!this.#validStringIndex(base, index)) return null;
    const checkedBase = base!;
    const table = context.version >= 5 ? await this.#byBase(".debug_str_offsets", checkedBase) : null;
    if (context.version >= 5 && !table) return null;
    return this.#stringEntry(table, checkedBase, index, context.format);
  }

  async #stringEntry(table: Contribution | null, base: bigint,
    index: bigint, format: 32 | 64): Promise<bigint | null> {
    const width = (table?.format ?? format) / 8;
    const offset = base + index * BigInt(width);
    if (table && !validStringOffset(table, offset)) {
      this.#issues.push(".debug_str_offsets: index outside its contribution.");
      return null;
    }
    const cursor = this.cursor(".debug_str_offsets", offset, table?.end);
    return cursor ? cursor.unsigned(width) : null;
  }

  #validStringIndex(base: bigint | null, index: bigint): boolean {
    if (base != null && index >= 0n) return true;
    this.#issues.push("DW_FORM_strx requires a valid index and DW_AT_str_offsets_base in the unit root.");
    return false;
  }

  async #readAddress(unit: DwarfUnit, index: bigint, base: bigint | null): Promise<bigint | null> {
    if (!this.#validAddressIndex(base, index)) return null;
    const checkedBase = base!;
    const contribution = unit.version >= 5 ? await this.#byBase(".debug_addr", checkedBase) : null;
    if (unit.version >= 5 && !contribution) return null;
    const offset = checkedBase + index * BigInt(unit.addressSize);
    if (contribution && !this.#validAddressOffset(contribution, unit.addressSize, offset)) return null;
    const cursor = this.cursor(".debug_addr", offset, contribution?.end);
    return cursor ? cursor.unsigned(unit.addressSize) : null;
  }

  #validAddressIndex(base: bigint | null, index: bigint): boolean {
    if (base == null || index < 0n) {
      this.#issues.push("Indexed address requires a valid DW_AT_addr_base in the unit root.");
      return false;
    }
    return true;
  }

  #validAddressOffset(contribution: Contribution, addressSize: number, offset: bigint): boolean {
    if (contribution.addressSize === addressSize && offset + BigInt(addressSize) <= BigInt(contribution.end)) {
      return true;
    }
    this.#issues.push(".debug_addr: index outside its contribution or address-size mismatch.");
    return false;
  }

  async listCursor(unit: DwarfUnit, attribute: DwarfAttribute, name: string): Promise<DwarfCursor | null> {
    const value = dwarfNumericValue(attribute.value);
    if (value == null) return null;
    if (unit.version < 5) return this.cursor(name, value);
    const indexed = attribute.form === DWARF_FORM.rangeListIndex ||
      attribute.form === DWARF_FORM.locationListIndex;
    const contribution = indexed ? await this.#listContribution(unit, name)
      : (await this.#tables(name)).find(item => value >= BigInt(item.entriesOffset +
        item.offsetCount * (item.format / 8)) && value < BigInt(item.end));
    if (!contribution || contribution.addressSize !== unit.addressSize) {
      this.#issues.push(`${name}: list offset has no matching contribution or address-size mismatch.`);
      return null;
    }
    const offset = indexed ? await this.#listOffset(contribution, name, value) : value;
    return offset == null ? null : this.cursor(name, offset, contribution.end);
  }

  async #listOffset(table: Contribution, name: string, index: bigint): Promise<bigint | null> {
    if (index < 0n || index >= BigInt(table.offsetCount)) {
      this.#issues.push(`${name}: list index ${index} outside its contribution offset table.`);
      return null;
    }
    const cursor = this.cursor(name, BigInt(table.entriesOffset) + index * BigInt(table.format / 8), table.end);
    const relative = await cursor?.unsigned(table.format / 8);
    if (relative == null) return null;
    const offset = BigInt(table.entriesOffset) + relative;
    if (offset < BigInt(table.entriesOffset + table.offsetCount * (table.format / 8)) ||
        offset >= BigInt(table.end)) {
      this.#issues.push(`${name}: indexed list offset outside the contribution payload.`);
      return null;
    }
    return offset;
  }

  async #listContribution(unit: DwarfUnit, name: string): Promise<Contribution | null> {
    const base = dwarfNumericValue(dwarfAttributeValue(unit.dies[0],
      name === ".debug_rnglists" ? DWARF_ATTRIBUTE.rangeListsBase : DWARF_ATTRIBUTE.locationListsBase));
    if (base == null) {
      if (unit.sectionName.endsWith(".dwo")) return (await this.#tables(name))[0] ?? null;
      this.#issues.push(`${name}: indexed list requires a base attribute in the unit root.`);
      return null;
    }
    return this.#byBase(name, base);
  }

  async #byBase(name: string, base: bigint): Promise<Contribution | null> {
    const table = (await this.#tables(name)).find(item => BigInt(item.entriesOffset) === base);
    if (!table) this.#issues.push(`${name}: base ${base} does not identify a contribution table.`);
    return table ?? null;
  }

  #tables(name: string): Promise<Contribution[]> {
    if (!this.#contributions.has(name)) this.#contributions.set(name, this.#readTables(name));
    return this.#contributions.get(name)!;
  }

  async #readTables(name: string): Promise<Contribution[]> {
    const source = this.#sections.get(name);
    if (!source) { this.#issues.push(`${name}: indexed section is missing.`); return []; }
    const tables: Contribution[] = [];
    let offset = 0;
    while (offset < source.section.size) {
      const table = await readContribution(source, offset, this.#byteOrder, this.#issues);
      if (!table) break;
      tables.push(table);
      offset = table.end;
    }
    return tables;
  }
}
