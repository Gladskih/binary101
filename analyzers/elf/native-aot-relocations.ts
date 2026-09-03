"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfNativeAotImage } from "./native-aot-image.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { vaddrToFileOffset } from "./vaddr-to-file-offset.js";

const PT_DYNAMIC = 2;
const SHT_RELA = 4;
const SHT_REL = 9;
const SHF_ALLOC = 0x2n;
const DT_NULL = 0n;
const DT_RELA = 7n;
const DT_RELASZ = 8n;
const DT_RELAENT = 9n;
const DT_REL = 17n;
const DT_RELSZ = 18n;
const DT_RELENT = 19n;

type ElfRelativeArchitecture = { pointerSize: 8; relocationType: number };
type ElfRelocationEncoding = "rel" | "rela";
type ElfRelocationTable = {
  offset: number;
  size: number;
  entrySize: number;
  encoding: ElfRelocationEncoding;
};

export interface ElfNativeAotRelocations {
  sites: ReadonlySet<number>;
  targets: ReadonlyMap<number, number>;
}

// Values follow the official processor-specific ELF ABI relocation enumerations.
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/x86_64.def
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELFRelocs/AArch64.def
export const getElfRelativeArchitecture = (
  machine: number,
  is64: boolean,
  littleEndian: boolean
): ElfRelativeArchitecture | null => {
  if (!littleEndian) return null;
  if (machine === 62 && is64) return { pointerSize: 8, relocationType: 8 };
  if (machine === 183 && is64) return { pointerSize: 8, relocationType: 1027 };
  return null;
};

const toSafeRange = (offset: bigint, size: bigint, fileSize: number): [number, number] | null => {
  const numericOffset = Number(offset);
  const numericSize = Number(size);
  if (offset < 0n || size <= 0n || !Number.isSafeInteger(numericOffset) ||
    !Number.isSafeInteger(numericSize) || numericOffset + numericSize > fileSize) return null;
  return [numericOffset, numericSize];
};

const sectionTables = (
  sections: ElfSectionHeader[],
  fileSize: number,
  issues: string[]
): ElfRelocationTable[] => sections.flatMap(section => {
  if ((section.type !== SHT_REL && section.type !== SHT_RELA) || !(section.flags & SHF_ALLOC)) {
    return [];
  }
  const encoding = section.type === SHT_RELA ? "rela" : "rel";
  const expectedSize = encoding === "rela" ? 24 : 16;
  const range = toSafeRange(section.offset, section.size, fileSize);
  const entrySize = Number(section.entsize);
  if (!range || entrySize !== expectedSize || range[1] % entrySize !== 0) {
    issues.push(`ELF relocation section ${section.name ?? `#${section.index}`} is malformed.`);
    return [];
  }
  return [{ offset: range[0], size: range[1], entrySize, encoding }];
});

const readDynamicTags = async (
  reader: FileRangeReader,
  programHeaders: ElfProgramHeader[],
  littleEndian: boolean,
  issues: string[]
): Promise<Map<bigint, bigint> | null> => {
  const dynamic = programHeaders.find(header => header.type === PT_DYNAMIC && header.filesz > 0n);
  if (!dynamic) return null;
  const range = toSafeRange(dynamic.offset, dynamic.filesz, reader.size);
  const entrySize = 16;
  if (!range || range[1] % entrySize !== 0) {
    issues.push("ELF PT_DYNAMIC table is malformed; NativeAOT relocations were not used.");
    return null;
  }
  const tags = new Map<bigint, bigint>();
  for (let offset = range[0]; offset < range[0] + range[1]; offset += entrySize) {
    const view = await reader.read(offset, entrySize);
    if (view.byteLength !== entrySize) return null;
    const tag = view.getBigInt64(0, littleEndian);
    if (tag === DT_NULL) break;
    const value = view.getBigUint64(8, littleEndian);
    const existing = tags.get(tag);
    if (existing != null && existing !== value) {
      issues.push("ELF PT_DYNAMIC contains conflicting relocation tags.");
      return null;
    }
    tags.set(tag, value);
  }
  return tags;
};

const dynamicTable = (
  tags: Map<bigint, bigint>,
  programHeaders: ElfProgramHeader[],
  addressTag: bigint,
  sizeTag: bigint,
  entryTag: bigint,
  encoding: ElfRelocationEncoding,
  fileSize: number,
  issues: string[]
): ElfRelocationTable | null => {
  const address = tags.get(addressTag);
  const size = tags.get(sizeTag);
  const entrySize = tags.get(entryTag);
  if (address == null && size == null && entrySize == null) return null;
  const fileOffset = address == null ? null : vaddrToFileOffset(programHeaders, address);
  const range = fileOffset == null || size == null ? null : toSafeRange(fileOffset, size, fileSize);
  const numericEntrySize = entrySize == null ? 0 : Number(entrySize);
  if (!range || numericEntrySize !== (encoding === "rela" ? 24 : 16) ||
    range[1] % numericEntrySize !== 0) {
    issues.push(`ELF dynamic ${encoding.toUpperCase()} table is malformed.`);
    return null;
  }
  return { offset: range[0], size: range[1], entrySize: numericEntrySize, encoding };
};

const dynamicTables = async (
  reader: FileRangeReader,
  programHeaders: ElfProgramHeader[],
  littleEndian: boolean,
  issues: string[]
): Promise<ElfRelocationTable[]> => {
  const tags = await readDynamicTags(reader, programHeaders, littleEndian, issues);
  if (!tags) return [];
  return [
    dynamicTable(
      tags, programHeaders, DT_RELA, DT_RELASZ, DT_RELAENT, "rela", reader.size, issues
    ),
    dynamicTable(
      tags, programHeaders, DT_REL, DT_RELSZ, DT_RELENT, "rel", reader.size, issues
    )
  ].filter((table): table is ElfRelocationTable => table != null);
};

const readRelocation = async (
  reader: FileRangeReader,
  table: ElfRelocationTable,
  offset: number,
  architecture: ElfRelativeArchitecture,
  littleEndian: boolean,
  image: ElfNativeAotImage
): Promise<[number, number] | null> => {
  const view = await reader.read(offset, table.entrySize);
  if (view.byteLength !== table.entrySize) return null;
  const location = view.getBigUint64(0, littleEndian);
  const info = view.getBigUint64(8, littleEndian);
  const type = Number(info & 0xffff_ffffn);
  const symbol = info >> 32n;
  if (type !== architecture.relocationType || symbol !== 0n) return null;
  const site = image.toImageAddress(location);
  if (site == null || !image.isDataRange(site, architecture.pointerSize, architecture.pointerSize)) {
    return null;
  }
  const targetVirtualAddress = table.encoding === "rela"
    ? view.getBigInt64(16, littleEndian)
    : await image.readPointerValue(site);
  if (targetVirtualAddress == null || targetVirtualAddress < 0n) return null;
  const target = image.toImageAddress(targetVirtualAddress);
  return target == null ? null : [site, target];
};

export const indexElfNativeAotRelocations = async (
  reader: FileRangeReader,
  programHeaders: ElfProgramHeader[],
  sections: ElfSectionHeader[],
  architecture: ElfRelativeArchitecture,
  littleEndian: boolean,
  image: ElfNativeAotImage,
  issues: string[]
): Promise<ElfNativeAotRelocations | null> => {
  const fromSections = sectionTables(sections, reader.size, issues);
  const tables = fromSections.length
    ? fromSections
    : await dynamicTables(reader, programHeaders, littleEndian, issues);
  const targets = new Map<number, number>();
  for (const table of tables) {
    for (let offset = table.offset; offset < table.offset + table.size; offset += table.entrySize) {
      const relocation = await readRelocation(
        reader, table, offset, architecture, littleEndian, image
      );
      if (!relocation) continue;
      const existing = targets.get(relocation[0]);
      if (existing != null && existing !== relocation[1]) {
        issues.push("Conflicting ELF relative relocations prevent reliable NativeAOT analysis.");
        return null;
      }
      targets.set(relocation[0], relocation[1]);
    }
  }
  return targets.size ? { sites: new Set(targets.keys()), targets } : null;
};
