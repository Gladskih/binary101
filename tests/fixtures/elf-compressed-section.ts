import type { ElfSectionHeader } from "../../analyzers/elf/types.js";
import { encodeElfCompressedSection } from "./dwarf-compressed-section-fixture.js";

// gABI 3.7: Elf64_Chdr is 24 bytes, Elf32_Chdr is 12 bytes.
export const compressElfFixtureSection = (
  bytes: Uint8Array, section: ElfSectionHeader, offset: number,
  format: { bits: 32 | 64; littleEndian: boolean; codec: "zlib" | "zstd" }
): void => {
  const original = bytes.subarray(Number(section.offset), Number(section.offset + section.size));
  const compressed = encodeElfCompressedSection(original, format.bits === 64 ? "elf64" : "elf32",
    format.littleEndian ? "little" : "big", section.size, format.codec === "zlib" ? 1 : 2);
  bytes.set(compressed, offset);
  section.flags |= 0x800n;
  section.offset = BigInt(offset);
  section.size = BigInt(compressed.length);
  section.addralign = BigInt(format.bits / 8);
};
