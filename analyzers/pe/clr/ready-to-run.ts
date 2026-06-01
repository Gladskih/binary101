"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrHeader } from "./types.js";
import type { PeClrReadyToRun, PeClrReadyToRunSection } from "./ready-to-run-types.js";

const readyToRunSectionName = (type: number): string => {
  // Section type ids come from CoreCLR readytorun.h:
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
  switch (type) {
    case 100: return "CompilerIdentifier";
    case 101: return "ImportSections";
    case 102: return "RuntimeFunctions";
    case 103: return "MethodDefEntryPoints";
    case 104: return "ExceptionInfo";
    case 105: return "DebugInfo";
    case 106: return "DelayLoadMethodCallThunks";
    case 108: return "AvailableTypes";
    case 109: return "InstanceMethodEntryPoints";
    case 110: return "InliningInfo";
    case 111: return "ProfileDataInfo";
    case 112: return "ManifestMetadata";
    case 113: return "AttributePresence";
    case 114: return "InliningInfo2";
    case 115: return "ComponentAssemblies";
    case 116: return "OwnerCompositeExecutable";
    case 117: return "PgoInstrumentationData";
    case 118: return "ManifestAssemblyMvids";
    case 119: return "CrossModuleInlineInfo";
    case 120: return "HotColdMap";
    case 121: return "MethodIsGenericMap";
    case 122: return "EnclosingTypeMap";
    case 123: return "TypeGenericInfoMap";
    case 124: return "ExternalTypeMaps";
    case 125: return "ProxyTypeMaps";
    case 126: return "TypeMapAssemblyTargets";
    default: return `Unknown(${type})`;
  }
};

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

export const parseReadyToRun = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader
): Promise<PeClrReadyToRun> => {
  if (clr.ManagedNativeHeaderRVA === 0 && clr.ManagedNativeHeaderSize === 0) {
    return emptyReadyToRun("absent", []);
  }
  const offset = rvaToOff(clr.ManagedNativeHeaderRVA);
  if (offset == null || offset < 0 || offset >= reader.size) {
    return emptyReadyToRun("unmapped", ["ManagedNativeHeader RVA could not be mapped to a file offset."]);
  }
  // ReadyToRunCoreHeader fixed fields through NumberOfSections occupy 16 bytes.
  const header = await reader.read(offset, Math.min(clr.ManagedNativeHeaderSize, 16));
  if (header.byteLength < 16) return emptyReadyToRun("truncated", ["ManagedNativeHeader is shorter than 16 bytes."]);
  const signature = header.getUint32(0, true);
  const majorVersion = header.getUint16(4, true);
  const minorVersion = header.getUint16(6, true);
  const flags = header.getUint32(8, true);
  const sectionCount = header.getUint32(12, true);
  // READYTORUN_SIGNATURE is ASCII "RTR" stored little-endian as 0x00525452.
  if (signature !== 0x00525452) {
    return {
      status: "unknown-managed-native-header",
      signature,
      majorVersion,
      minorVersion,
      flags,
      sectionCount: 0,
      sections: [],
      issues: []
    };
  }
  const sectionBytes = sectionCount * 12;
  const issues: string[] = [];
  // Defensive local cap; real section counts are small, malformed files can claim billions.
  if (sectionCount > 4096) {
    return {
      status: "ready-to-run",
      signature,
      majorVersion,
      minorVersion,
      flags,
      sectionCount,
      sections: [],
      issues: ["ReadyToRun section count is unreasonable; section table was not parsed."]
    };
  }
  const declaredTableBytes = Math.max(0, clr.ManagedNativeHeaderSize - 16);
  const table = await reader.read(offset + 16, Math.min(sectionBytes, declaredTableBytes));
  if (table.byteLength < sectionBytes) issues.push("ReadyToRun section table is truncated.");
  const sections: PeClrReadyToRunSection[] = [];
  for (let sectionOffset = 0; sectionOffset + 12 <= table.byteLength; sectionOffset += 12) {
    const type = table.getUint32(sectionOffset, true);
    sections.push({
      type,
      name: readyToRunSectionName(type),
      rva: table.getUint32(sectionOffset + 4, true),
      size: table.getUint32(sectionOffset + 8, true)
    });
  }
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
