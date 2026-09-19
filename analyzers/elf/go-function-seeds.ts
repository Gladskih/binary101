import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { parseGoPcHeader } from "../go-runtime/parser.js";
import { parseGoFunctionTable } from "../go-runtime/tables.js";
import type { GoRuntimeAddressSpace } from "../go-runtime/types.js";
import { elfFileRange } from "./relocation-reader.js";
import type { ElfSectionHeader } from "./types.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";

function addressSpace(reader: FileRangeReader, section: ElfSectionHeader,
  text: ElfSectionHeader, pointerSize: 4 | 8): GoRuntimeAddressSpace {
  return {
    pointerSize,
    isMappedRange: (address, size) => Number.isSafeInteger(size) && size >= 0 &&
      address >= section.addr && address + BigInt(size) <= section.addr + BigInt(reader.size),
    readMapped: async (address, size) => {
      const range = elfFileRange(address - section.addr, BigInt(size), reader.size);
      return range ? reader.readBytes(range.offset, range.size) : null;
    },
    isExecutableRange: (start, end) => start >= text.addr && end > start &&
      end <= text.addr + text.size
  };
}

async function collectStarts(reader: FileRangeReader, section: ElfSectionHeader,
  text: ElfSectionHeader): Promise<bigint[] | null> {
  const prefix = await reader.read(0, 8);
  if (prefix.byteLength !== 8) return null;
  const pointerSize = prefix.getUint8(7);
  if (pointerSize !== 4 && pointerSize !== 8) return null;
  const image = addressSpace(reader, section, text, pointerSize);
  const header = await parseGoPcHeader(image, section.addr);
  if (!header) return null;
  // parseGoPcHeader validates exactly five ordered, positive table offsets.
  const names = header.tableOffsets[0]!;
  const functions = header.tableOffsets[4]!;
  if (functions >= BigInt(reader.size)) return null;
  return (await parseGoFunctionTable(image, header,
    { address: section.addr + names, length: Number(header.tableOffsets[1]! - names) },
    { address: section.addr + functions, length: reader.size - Number(functions) }, text.addr))
    ?.map(fn => fn.start) ?? null;
}

export const collectGoFunctionSeeds = async (file: File, sections: ElfSectionHeader[],
  issues: string[]): Promise<ElfDisassemblySeedGroup[]> => {
  const section = sections.find(section => section.name === ".gopclntab" ||
    section.name === ".data.rel.ro.gopclntab");
  if (!section) return [];
  // Go's ELF adapter supplies .text.Addr even when pcHeader.textStart is unrelocated.
  // https://go.dev/src/cmd/internal/objfile/elf.go
  // SHF_EXECINSTR = 4: https://gabi.xinuos.com/elf/03-sheader.html
  const text = sections.find(section => section.name === ".text" && (section.flags & 4n) !== 0n);
  const range = elfFileRange(section.offset, section.size, file.size);
  const starts = range && text && elfFileRange(text.offset, text.size, file.size) &&
    await collectStarts(createFileRangeReader(file, range.offset, range.size), section, text);
  if (!starts) {
    issues.push("Go function metadata is invalid, truncated or uses an unsupported layout/byte order.");
    return [];
  }
  return [{ source: ".gopclntab functions", vaddrs: starts }];
};
