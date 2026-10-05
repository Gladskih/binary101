"use strict";

import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrHeader } from "./types.js";
import { decodeReadyToRunSections } from "./ready-to-run-sections.js";
import { readyToRunPointerSize } from "./ready-to-run-target.js";
import { validateReadyToRunReferences } from "./ready-to-run-references.js";
import {
  READY_TO_RUN_SECTION_EXCEPTION_INFO,
  READY_TO_RUN_SECTION_RUNTIME_FUNCTIONS,
  type PeClrReadyToRun,
  type PeClrReadyToRunSection
} from "./ready-to-run-types.js";

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
const emptyReadyToRun = (
  status: PeClrReadyToRun["status"],
  issues: string[]
): PeClrReadyToRun => ({
  status,
  signature: null,
  majorVersion: null,
  minorVersion: null,
  flags: null,
  sectionCount: 0,
  sections: [],
  issues
});

const parseSections = async (
  reader: FileRangeReader, rvaToOff: RvaToOffset, clr: PeClrHeader,
  sectionCount: number, issues: string[]
): Promise<PeClrReadyToRunSection[]> => {
  // READYTORUN_SECTION is a uint32 type followed by IMAGE_DATA_DIRECTORY (12 bytes).
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  const sectionBytes = sectionCount * 12;
  const declaredTableBytes = Math.max(0, clr.ManagedNativeHeaderSize - 16);
  const table = await readMappedRvaPrefix(reader, clr.ManagedNativeHeaderRVA + 16,
    Math.min(sectionBytes, declaredTableBytes), rvaToOff);
  if (table.byteLength < sectionBytes) issues.push("ReadyToRun section table is truncated.");
  const sections: PeClrReadyToRunSection[] = [];
  for (let offset = 0; offset + 12 <= table.byteLength; offset += 12) {
    const type = table.getUint32(offset, true);
    sections.push({ type, name: readyToRunSectionName(type),
      rva: table.getUint32(offset + 4, true), size: table.getUint32(offset + 8, true) });
  }
  if (sections.some((section, index) => index > 0 && section.type <= sections[index - 1]!.type)) {
    issues.push("ReadyToRun section types are not in strictly increasing order.");
  }
  return sections;
};

const classifyNativeHeader = (signature: number): PeClrReadyToRun => ({
  // NGen's version-specific CORCOMPILE_HEADER must not be read as ReadyToRun.
  // https://raw.githubusercontent.com/dotnet/coreclr/master/src/inc/corcompile.h
  ...emptyReadyToRun(signature === 0x0045474e ? "ngen" : "unknown-managed-native-header", []),
  signature
});

export const parseReadyToRun = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader,
  machine?: number
): Promise<PeClrReadyToRun> => {
  if (clr.ManagedNativeHeaderRVA === 0 && clr.ManagedNativeHeaderSize === 0) {
    return emptyReadyToRun("absent", []);
  }
  const offset = rvaToOff(clr.ManagedNativeHeaderRVA);
  if (offset == null || offset < 0 || offset >= reader.size) {
    return emptyReadyToRun("unmapped", ["ManagedNativeHeader RVA could not be mapped to a file offset."]);
  }
  // ReadyToRunCoreHeader fixed fields through NumberOfSections occupy 16 bytes.
  const header = await readMappedRvaPrefix(reader, clr.ManagedNativeHeaderRVA,
    Math.min(clr.ManagedNativeHeaderSize, 16), rvaToOff);
  if (header.byteLength < 16) return emptyReadyToRun("truncated", ["ManagedNativeHeader is shorter than 16 bytes."]);
  const signature = header.getUint32(0, true);
  const majorVersion = header.getUint16(4, true);
  const minorVersion = header.getUint16(6, true);
  const flags = header.getUint32(8, true);
  const sectionCount = header.getUint32(12, true);
  // READYTORUN_SIGNATURE is ASCII "RTR" stored little-endian as 0x00525452.
  if (signature !== 0x00525452) return classifyNativeHeader(signature);
  const issues: string[] = [];
  const sections = await parseSections(reader, rvaToOff, clr, sectionCount, issues);
  await decodeReadyToRunSections(reader, rvaToOff, sections, readyToRunPointerSize(machine), issues);
  validateReadyToRunReferences(sections, machine, issues);
  return {
    status: "ready-to-run",
    signature,
    majorVersion,
    minorVersion,
    flags,
    sectionCount,
    sections,
    issues
  };
};
