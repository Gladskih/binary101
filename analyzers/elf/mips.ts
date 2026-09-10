import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfMipsMetadata } from "./mips-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readMipsAbiFlags, readMips32RegInfo, readMips64RegInfo } from "./mips-records.js";
import { readMipsOptions } from "./mips-options.js";
import type { ElfByteOrder } from "./binary-layout-types.js";

// MIPS section/program types: LLVM BinaryFormat/ELF.h.
// https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/BinaryFormat/ELF.h
const mipsSources = (elf: ElfParseResult) => {
  const sources = elf.sections.filter(section => [0x70000006, 0x7000000d, 0x7000002a].includes(section.type))
    .map(section => ({ type: section.type, offset: section.offset, size: section.size,
      source: `Section #${section.index}`, compressed: (section.flags & 0x800n) !== 0n }));
  for (const [type, segmentType] of [[0x70000006, 0x70000000], [0x7000002a, 0x70000003]]) {
    if (sources.some(source => source.type === type)) continue;
    const segment = elf.programHeaders.find(header => header.type === segmentType);
    if (segment) sources.push({ type: type!, offset: segment.offset, size: segment.filesz,
      source: `Segment #${segment.index}`, compressed: false });
  }
  return sources;
};

const readMipsSource = async (
  reader: FileRangeReader, elf: ElfParseResult, source: ReturnType<typeof mipsSources>[number]
): Promise<ElfMipsMetadata> => {
  const result: ElfMipsMetadata = { source: source.source, issues: [] };
  const range = elfFileRange(source.offset, source.size, reader.size);
  if (!range || source.compressed) {
    result.issues.push("MIPS metadata is compressed, truncated or outside the file.");
    return result;
  }
  const order = elf.littleEndian ? "little" : "big";
  const readRegInfo = elf.is64 ? readMips64RegInfo : readMips32RegInfo;
  if (source.type === 0x7000000d) {
    result.options = await readMipsOptions(reader, range, order, readRegInfo, result.issues);
    return result;
  }
  const view = await reader.read(range.offset, Math.min(range.size, 32));
  if (source.type === 0x7000002a) {
    decodeAbiFlags(view, order, result);
  } else {
    const registers = readRegInfo(view, order);
    if (registers) result.registerInfo = registers;
    else result.issues.push("MIPS register info is truncated.");
  }
  return result;
};

const decodeAbiFlags = (view: DataView, order: ElfByteOrder, result: ElfMipsMetadata): void => {
  const flags = readMipsAbiFlags(view, order);
  if (!flags) {
    result.issues.push("MIPS ABI flags are truncated.");
    return;
  }
  result.abiFlags = flags;
  if (flags.version !== 0) result.issues.push(`Unsupported MIPS ABI flags version ${flags.version}.`);
};

export const parseElfMips = async (file: File, elf: ElfParseResult): Promise<ElfMipsMetadata[]> => {
  if (elf.header.machine !== 8) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const results: ElfMipsMetadata[] = [];
  for (const source of mipsSources(elf)) results.push(await readMipsSource(reader, elf, source));
  return results;
};
