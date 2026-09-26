import type { FileRangeReader } from "../file-range-reader.js";
import type { DModuleInfo, DRuntimeImage, DRuntimeMetadata } from "../d-runtime/types.js";
import { parseDModuleInfo } from "../d-runtime/module-info.js";
import { readDPointer } from "../d-runtime/fields.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./optional-header/magic.js";
import { peSectionNameValue } from "./sections/name.js";
import type { PeSection, PeWindowsCore } from "./types.js";
import type { PeBaseRelocationResult } from "./directories/reloc.js";
import { findDModuleTableCandidates } from "./d-runtime-tables.js";
import { readDModuleTable } from "./d-runtime-table.js";
import { D_MODULE_INFO_LAYOUT } from "../d-runtime/layout.js";
import { COFF_SECTION_CHARACTERISTICS } from "../coff/layout.js";

const mappedSize = (section: PeSection): number =>
  Math.min(section.sizeOfRawData, section.virtualSize || section.sizeOfRawData);

const createDImage = (reader: FileRangeReader, core: PeWindowsCore): DRuntimeImage => ({
  pointerSize: core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 8 : 4,
  littleEndian: true,
  isMapped: (address, size) => core.sections.some(section => {
    const relative = address - core.opt.ImageBase - BigInt(section.virtualAddress);
    return Number.isSafeInteger(size) && size > 0 && relative >= 0n &&
      relative + BigInt(size) <= BigInt(mappedSize(section)) &&
      section.pointerToRawData + Number(relative) + size <= reader.size;
  }),
  read: async (address, size) => {
    const rva = address - core.opt.ImageBase;
    const section = core.sections.find(candidate => rva >= BigInt(candidate.virtualAddress) &&
      rva < BigInt(candidate.virtualAddress) + BigInt(mappedSize(candidate)));
    if (!section || !Number.isSafeInteger(size) || size <= 0) return null;
    const relative = Number(rva - BigInt(section.virtualAddress));
    return reader.read(section.pointerToRawData + relative,
      Math.min(size, mappedSize(section) - relative));
  },
  isExecutable: address => core.sections.some(section =>
    (section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) !== 0 &&
    address >= core.opt.ImageBase + BigInt(section.virtualAddress) &&
    address < core.opt.ImageBase + BigInt(section.virtualAddress) + BigInt(mappedSize(section)) &&
    section.pointerToRawData + Number(address - core.opt.ImageBase -
      BigInt(section.virtualAddress)) < reader.size)
});

const collectModules = async (
  table: AsyncIterable<bigint>, image: DRuntimeImage, result: DRuntimeMetadata
): Promise<void> => {
  const seen = new Set<bigint>();
  for await (const address of table) {
    if (seen.has(address)) continue;
    seen.add(address);
    const module = await parseDModuleInfo(image, address);
    if (!module) {
      result.warnings.push(`Invalid or unsupported D ModuleInfo at 0x${address.toString(16)}.`);
      continue;
    }
    result.modules.push(module);
  }
};

export const analyzePeDRuntime = async (
  file: Blob, reader: FileRangeReader, core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null = null
): Promise<DRuntimeMetadata | null> => {
  // Prefer the runtime's exact section name; renamed discovery uses parsed relocations.
  // https://github.com/dlang/dmd/blob/v2.112.0/druntime/src/rt/sections_win64.d#L350-L358
  const sections = core.sections.filter(section => peSectionNameValue(section.name) === ".minfo");
  if (!sections.length) return discoverRenamedTable(file, reader, core, relocations);
  const result: DRuntimeMetadata = { modules: [], warnings: [] };
  if (sections.length !== 1) {
    result.warnings.push("Multiple D .minfo sections; module table is ambiguous.");
    return result;
  }
  const image = createDImage(reader, core);
  try {
    await collectModules(readDModuleTable(file, reader, sections[0]!, image, result.warnings),
      image, result);
    if (!result.modules.length) result.warnings.push("D .minfo contains no validated ModuleInfo.");
  } catch {
    result.warnings.push("Could not read D runtime metadata.");
  }
  return result;
};

const readCandidateModule = async (address: bigint, image: DRuntimeImage,
  cache: Map<bigint, DModuleInfo | null>): Promise<DModuleInfo | null> => {
  // Reject function-pointer tables before reading their executable targets.
  if (address === 0n || !image.isMapped(address, D_MODULE_INFO_LAYOUT.headerBytes) ||
    image.isExecutable(address)) return null;
  if (!cache.has(address)) cache.set(address, await parseDModuleInfo(image, address));
  return cache.get(address)!;
};

const parseStrictTable = async (table: AsyncIterable<bigint>, image: DRuntimeImage,
  cache: Map<bigint, DModuleInfo | null>)
  : Promise<DRuntimeMetadata | null> => {
  const result: DRuntimeMetadata = { modules: [], warnings: [] };
  const addresses = new Set<bigint>();
  for await (const address of table) {
    if (addresses.has(address)) continue;
    const module = await readCandidateModule(address, image, cache);
    if (!module) return null;
    addresses.add(address);
    result.modules.push(module);
  }
  // One record alone cannot provide independent structural confirmation.
  return result.modules.length > 1 && result.modules.every(module =>
    module.importedModules.every(address => addresses.has(address))) ? result : null;
};

const discoverRenamedTable = async (file: Blob, reader: FileRangeReader, core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null): Promise<DRuntimeMetadata | null> => {
  const image = createDImage(reader, core);
  const results: DRuntimeMetadata[] = [];
  // Overlapping candidate tables can reference the same records; decode each address once.
  const cache = new Map<bigint, DModuleInfo | null>();
  for (const candidate of findDModuleTableCandidates(core, relocations, image.pointerSize)) {
    try {
      const view = await reader.read(candidate.section.pointerToRawData +
        candidate.firstPointerOffset, image.pointerSize);
      if (view.byteLength !== image.pointerSize) continue;
      // Probe one relocated record before walking any candidate table, regardless of size.
      if (!await readCandidateModule(readDPointer(image, view), image, cache)) continue;
      const warnings: string[] = [];
      const result = await parseStrictTable(readDModuleTable(file, reader, candidate.section,
        image, warnings), image, cache);
      if (warnings.length) continue;
      if (result) results.push(result);
    } catch {
      continue;
    }
  }
  if (results.length > 1) {
    return { modules: [], warnings: ["Multiple validated D module tables; discovery is ambiguous."] };
  }
  return results[0] ?? null;
};
