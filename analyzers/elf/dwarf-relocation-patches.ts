import type { DwarfSectionSource } from "../dwarf/types.js";
import type { ElfRelocation, ElfRelocationImage } from "./relocation-types.js";
import type { ElfDwarfPatch, ElfDwarfRelocationKind } from "./dwarf-relocation-types.js";
import { elfDwarfRelocationKind } from "./dwarf-relocation-kinds.js";
import { elfDwarfRelocationValue } from "./dwarf-relocation-value.js";

const readInteger = (view: DataView, littleEndian: boolean): bigint => {
  let value = 0n;
  for (let index = 0; index < view.byteLength; index += 1) {
    value = value * 256n + BigInt(view.getUint8(littleEndian ? view.byteLength - index - 1 : index));
  }
  return value;
};
const integerBytes = (value: bigint, width: number, littleEndian: boolean): Uint8Array => {
  const bytes = new Uint8Array(width);
  for (let index = 0; index < width; index += 1) {
    bytes[littleEndian ? index : width - index - 1] = Number((value >> BigInt(index * 8)) & 255n);
  }
  return bytes;
};
const composable = (kind: ElfDwarfRelocationKind): boolean =>
  kind.operation === "add" || kind.operation === "subtract";

type RelocatedField = { original: bigint; current: bigint; kind: ElfDwarfRelocationKind };

const validSourceRange = (source: DwarfSectionSource): boolean =>
  [source.section.offset, source.section.size, source.summary.offset].every(Number.isSafeInteger) &&
  source.section.offset >= 0 && source.section.size >= 0 && source.summary.offset >= 0;

const compatibleFields = (previous: RelocatedField | undefined, kind: ElfDwarfRelocationKind): boolean =>
  previous == null || (previous.kind.width === kind.width && composable(previous.kind) && composable(kind));

const fieldOffset = (source: DwarfSectionSource, entry: ElfRelocation,
  kind: ElfDwarfRelocationKind, issues: string[]): number | null => {
  const offset = Number(entry.target?.sectionOffset);
  if (entry.target?.sectionOffset != null && Number.isSafeInteger(offset) && offset >= 0 &&
      offset + kind.width <= source.section.size) return offset;
  issues.push("DWARF relocation write is outside its target section.");
  return null;
};

class RelocationPatches {
  readonly #source: DwarfSectionSource;
  readonly #elf: ElfRelocationImage;
  readonly #issues: string[];
  readonly #sections: Map<number, ElfRelocationImage["sections"][number]>;
  // Composed relocations reuse both the original addend and the current value of one slot.
  readonly #fields = new Map<number, RelocatedField>();

  constructor(source: DwarfSectionSource, elf: ElfRelocationImage, issues: string[]) {
    this.#source = source;
    this.#elf = elf;
    this.#issues = issues;
    this.#sections = new Map(elf.sections.map(section => [section.index, section]));
  }

  async add(entry: ElfRelocation): Promise<boolean> {
    if (entry.type === 0 || (this.#elf.header.machine === 183 && entry.type === 256)) return true;
    const kind = entry.type == null ? null : elfDwarfRelocationKind(this.#elf.header.machine, entry.type);
    if (!kind) {
      this.#issues.push(
        `Unsupported DWARF relocation type ${entry.type} for machine ${this.#elf.header.machine}.`);
      return false;
    }
    const offset = fieldOffset(this.#source, entry, kind, this.#issues);
    return offset == null ? false : this.#write(entry, kind, offset);
  }

  async #write(entry: ElfRelocation, kind: ElfDwarfRelocationKind, offset: number): Promise<boolean> {
    const previous = this.#fields.get(offset);
    if (!compatibleFields(previous, kind)) {
      this.#issues.push("DWARF relocation writes overlap without a supported composition rule.");
      return false;
    }
    const original = previous?.original ?? await originalField(
      this.#source, offset, kind.width, this.#elf, this.#issues);
    if (original == null) return false;
    const value = this.#value(entry, kind, offset, original, previous?.current ?? original);
    if (typeof value === "string") { this.#issues.push(`${value}.`); return false; }
    this.#fields.set(offset, { original, current: value, kind });
    return true;
  }

  #value(entry: ElfRelocation, kind: ElfDwarfRelocationKind, offset: number,
    original: bigint, current: bigint): bigint | string {
    const target = this.#sections.get(entry.target!.sectionIndex!);
    if (!target || target.name !== this.#source.summary.name ||
        target.offset !== BigInt(this.#source.summary.offset)) {
      return "DWARF relocation target section disagrees with its source";
    }
    return elfDwarfRelocationValue(entry, kind, this.#elf, this.#sections,
      target.addr + BigInt(offset), original, current);
  }

  patches(): ElfDwarfPatch[] | null {
    return disjointPatches(this.#source, this.#fields, this.#elf.littleEndian, this.#issues);
  }
}

export const buildElfDwarfRelocationPatches = async (source: DwarfSectionSource,
  entries: ElfRelocation[], elf: ElfRelocationImage, issues: string[]): Promise<ElfDwarfPatch[] | null> => {
  if (!validSourceRange(source)) { issues.push("DWARF relocation source has an invalid section range."); return null; }
  const builder = new RelocationPatches(source, elf, issues);
  for (const entry of entries) if (!await builder.add(entry)) return null;
  return builder.patches();
};

const originalField = async (source: DwarfSectionSource, offset: number, width: number,
  elf: ElfRelocationImage, issues: string[]): Promise<bigint | null> => {
  const view = await source.reader.read(source.section.offset + offset, width);
  if (view.byteLength === width) return readInteger(view, elf.littleEndian);
  issues.push("DWARF relocation field is truncated.");
  return null;
};

const disjointPatches = (source: DwarfSectionSource,
  fields: Map<number, { current: bigint; kind: ElfDwarfRelocationKind }>, littleEndian: boolean,
  issues: string[]): ElfDwarfPatch[] | null => {
  const patches = [...fields].sort(([left], [right]) => left - right).map(([offset, field]) => ({
    offset: source.section.offset + offset, bytes: integerBytes(field.current, field.kind.width, littleEndian)
  }));
  if (patches.some((patch, index) => index > 0 &&
      patch.offset < patches[index - 1]!.offset + patches[index - 1]!.bytes.length)) {
    issues.push("DWARF relocation fields overlap.");
    return null;
  }
  return patches;
};
