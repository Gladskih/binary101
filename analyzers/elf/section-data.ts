import type { FileRangeReader } from "../file-range-reader.js";
import { createMemoryRangeReader } from "../memory-range-reader.js";
import { readElfCompressionPayload } from "../dwarf/compression-headers.js";
import { decompressSectionZlib } from "../section-zlib.js";
import { elfFileRange } from "./relocation-reader.js";
import type { ElfHeader, ElfParseResult, ElfSectionHeader } from "./types.js";
import { ELF_FILE_TYPE, ELF_SECTION_FLAG, ELF_SECTION_TYPE } from "./abi-constants.js";

export type ElfSectionData = { reader: FileRangeReader; offset: number; size: number; alignment: bigint };
export type ElfSectionFormat = Pick<ElfParseResult, "is64" | "littleEndian" | "header" | "sections">;
export type ElfSectionEncoding = Pick<ElfSectionFormat, "is64" | "littleEndian"> &
  { header?: Pick<ElfHeader, "type"> };

// gABI 3.7, SHF_COMPRESSED. Keep stored and logical ranges distinct.
// https://gabi.xinuos.com/elf/03-sheader.html#compressed-sections
export const ELF_SECTION_COMPRESSED = 0x800n;

export const hasCompressedSectionAt = (sections: ElfSectionHeader[], type: number, offset: number): boolean => {
  const start = BigInt(offset);
  return sections.some(section => section.type === type && (section.flags & ELF_SECTION_COMPRESSED) !== 0n &&
    start >= section.offset && start < section.offset + section.size);
};

// The browser codecs and memory reader materialize the payload. Bound both allocations.
const MAX_COMPRESSED_SECTION_BYTES = 64 * 1024 * 1024;

const decodeElfSection = async (
  source: ElfSectionData, name: string, elf: ElfSectionEncoding, issues: string[]
): Promise<ElfSectionData | null> => {
  const payload = await readElfCompressionPayload(source.reader,
    { name, offset: source.offset, size: source.size }, elf, issues);
  if (!payload) return null;
  if (payload.size > MAX_COMPRESSED_SECTION_BYTES || payload.uncompressedSize > MAX_COMPRESSED_SECTION_BYTES) {
    issues.push(`${name}: compressed section exceeds the 64 MiB decoding limit.`);
    return null;
  }
  try {
    const compressed = await source.reader.readBytes(payload.offset, payload.size);
    if (compressed.length !== payload.size) throw new Error("compressed payload is truncated");
    const bytes = payload.codec === "zlib" ? await decompressSectionZlib(compressed, payload.uncompressedSize) :
      await (await import("../dwarf/zstd.js")).decompressDwarfZstd(compressed, payload.uncompressedSize);
    return { reader: createMemoryRangeReader(bytes), offset: 0, size: bytes.length, alignment: payload.alignment };
  } catch (error) {
    issues.push(`${name}: ${payload.codec} decompression failed: ${error instanceof Error ? error.message : String(error)}.`);
    return null;
  }
};

export const openElfSectionData = async (
  reader: FileRangeReader, section: ElfSectionHeader, elf: ElfSectionEncoding, issues: string[]
): Promise<ElfSectionData | null> => {
  const name = section.name || `section #${section.index}`;
  if (section.type === ELF_SECTION_TYPE.NOBITS) {
    issues.push(`${name}: SHT_NOBITS has no file data.`);
    return null;
  }
  const range = elfFileRange(section.offset, section.size, reader.size);
  if (!range) {
    issues.push(`${name}: section data is truncated or outside the file.`);
    return null;
  }
  const source = { ...range, reader, alignment: section.addralign };
  if (!(section.flags & ELF_SECTION_COMPRESSED)) return source;
  if ((elf.header?.type === ELF_FILE_TYPE.EXEC || elf.header?.type === ELF_FILE_TYPE.DYN) &&
    (section.flags & ELF_SECTION_FLAG.ALLOC)) {
    issues.push(`${name}: allocated sections in executables and shared objects cannot be compressed.`);
    return null;
  }
  return decodeElfSection(source, name, elf, issues);
};
