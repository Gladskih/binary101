import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { isRvaRange } from "../rva-mapping.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrReadyToRunSection } from "./ready-to-run-types.js";
import { READY_TO_RUN_SECTION_EXCEPTION_INFO, READY_TO_RUN_SECTION_RUNTIME_FUNCTIONS } from
  "./ready-to-run-types.js";

// Section IDs are defined by CoreCLR readytorun.h.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
const readyToRunSectionNames: Readonly<Record<number, string>> = {
  100: "CompilerIdentifier", 101: "ImportSections",
  [READY_TO_RUN_SECTION_RUNTIME_FUNCTIONS]: "RuntimeFunctions", 103: "MethodDefEntryPoints",
  [READY_TO_RUN_SECTION_EXCEPTION_INFO]: "ExceptionInfo", 105: "DebugInfo",
  106: "DelayLoadMethodCallThunks", 108: "AvailableTypes", 109: "InstanceMethodEntryPoints",
  110: "InliningInfo", 111: "ProfileDataInfo", 112: "ManifestMetadata",
  113: "AttributePresence", 114: "InliningInfo2", 115: "ComponentAssemblies",
  116: "OwnerCompositeExecutable", 117: "PgoInstrumentationData", 118: "ManifestAssemblyMvids",
  119: "CrossModuleInlineInfo", 120: "HotColdMap", 121: "MethodIsGenericMap",
  122: "EnclosingTypeMap", 123: "TypeGenericInfoMap", 124: "ExternalTypeMaps",
  125: "ProxyTypeMaps", 126: "TypeMapAssemblyTargets"
};

const readyToRunSectionName = (type: number): string =>
  readyToRunSectionNames[type] ?? `Unknown(${type})`;

const appendSections = (table: DataView, sections: PeClrReadyToRunSection[], issues: string[]): void => {
  for (let offset = 0; offset + 12 <= table.byteLength; offset += 12) {
    const type = table.getUint32(offset, true);
    const section = { type, name: readyToRunSectionName(type),
      rva: table.getUint32(offset + 4, true), size: table.getUint32(offset + 8, true) };
    if (section.size && !isRvaRange(section.rva, section.size)) {
      issues.push(`${section.name} has an invalid RVA range.`);
    }
    sections.push(section);
  }
};

const isDirectoryRange = (rva: number, size: number, count: number): boolean =>
  Number.isSafeInteger(count) && count >= 0 && count <= 0xffffffff &&
  Number.isSafeInteger(size) && size >= 0 && isRvaRange(rva, Math.max(1, size));

export const readReadyToRunDirectory = async (
  reader: FileRangeReader, mapper: RvaToOffset, rva: number, size: number,
  count: number, issues: string[]
): Promise<PeClrReadyToRunSection[]> => {
  if (!isDirectoryRange(rva, size, count)) {
    issues.push("ReadyToRun section directory has an invalid range or count.");
    return [];
  }
  // READYTORUN_SECTION: type DWORD followed by an IMAGE_DATA_DIRECTORY (12 bytes).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  const sections: PeClrReadyToRunSection[] = [];
  // Bounded I/O buffers, with no limit on the number of directory entries.
  const chunkSize = Math.floor(64 * 1024 / 12) * 12;
  for (let offset = 0; offset < Math.min(count * 12, size); offset += chunkSize) {
    try {
      const requested = Math.min(chunkSize, count * 12 - offset, size - offset);
      const table = await readMappedRvaPrefix(reader, rva + offset, requested, mapper);
      appendSections(table, sections, issues);
      if (table.byteLength < requested) break;
    } catch (error) {
      issues.push(error instanceof Error ? error.message : "ReadyToRun directory read failed");
      break;
    }
  }
  if (sections.length < count) issues.push("ReadyToRun section table is truncated.");
  if (sections.some((section, index) => index > 0 && section.type <= sections[index - 1]!.type)) {
    issues.push("ReadyToRun section types are not in strictly increasing order.");
  }
  return sections;
};
