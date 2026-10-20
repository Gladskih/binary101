import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocation, ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";
import { readDwarfCompressionPayload } from "../dwarf/compression-headers.js";
import { decompressSectionZlib } from "../section-zlib.js";
import { readElfRelocationRecords } from "./relocation-records.js";
import { createMemoryRangeReader } from "../memory-range-reader.js";
import type { DwarfCompressionPayload } from "../dwarf/compression-headers.js";

const decodePayload = async (reader: FileRangeReader, payload: DwarfCompressionPayload): Promise<Uint8Array> => {
  const compressed = await reader.readBytes(payload.offset, payload.size);
  if (compressed.length !== payload.size) throw new Error("compressed relocation payload is truncated");
  return payload.codec === "zlib" ? await decompressSectionZlib(compressed, payload.uncompressedSize) :
    await (await import("../dwarf/zstd.js")).decompressDwarfZstd(compressed, payload.uncompressedSize);
};

// SHF_COMPRESSED sections begin with Elf32/64_Chdr, not a relocation record.
// Reuse the gABI compression codecs used by DWARF; only the bounded section is read.
// https://gabi.xinuos.com/elf/03-sheader.html#compressed-sections
export async function* readElfCompressedRelocations(
  reader: FileRangeReader, table: ElfRelocationTable, elf: ElfRelocationImage,
  tableIndex: number, issues: string[]
): AsyncGenerator<ElfRelocation> {
  const section = elf.sections.find(section => section.index === table.sectionIndex);
  if (!section || section.flags & 2n) {
    issues.push("ELF compressed relocations require a non-allocated section.");
    return;
  }
  const payload = await readDwarfCompressionPayload(reader,
    { name: section.name || `section #${section.index}`, offset: table.offset, size: table.size, compressed: true },
    { kind: "elf", elfClass: elf.is64 ? "elf64" : "elf32", byteOrder: elf.littleEndian ? "little" : "big" }, issues);
  if (!payload) return;
  try {
    const bytes = await decodePayload(reader, payload);
    const decoded = { ...table, offset: 0, size: bytes.length };
    delete decoded.compressed;
    yield* readElfRelocationRecords(createMemoryRangeReader(bytes), decoded, elf, tableIndex, issues);
    table.complete = decoded.complete === true;
  } catch (error) {
    issues.push(`ELF compressed relocations: ${error instanceof Error ? error.message : String(error)}.`);
  }
}
