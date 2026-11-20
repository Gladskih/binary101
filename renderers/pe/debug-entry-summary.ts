"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { IMAGE_DEBUG_TYPE_ILTCG } from "../../analyzers/pe/debug/types.js";
import { contiguousRvaOffset } from "../../analyzers/pe/rva-mapping.js";
import { getDebugTypeInfo } from "./debug-type-info.js";

type DebugStorageInfo = { label: string; description: string };

const UNRESOLVED_STORAGE: DebugStorageInfo = {
  label: "UNRESOLVED",
  description: "The raw data location does not resolve to a complete file range."
};

// PE Debug Directory: the RVA and file pointer describe the same payload.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
const getRvaStorageInfo = (
  pe: PeWindowsParseResult, entry: PeDebugDirectoryEntry
): DebugStorageInfo => {
  const offset = contiguousRvaOffset(pe.rvaToOff, entry.addressOfRawData, entry.sizeOfData, pe.fileSize);
  if (entry.pointerToRawData && offset !== entry.pointerToRawData) {
    return {
      label: "INCONSISTENT",
      description: "The RVA and file pointer do not resolve to the same file range for the full payload."
    };
  }
  return offset == null ? UNRESOLVED_STORAGE : {
    label: "MAPPED",
    description: "The RVA maps the full payload into the image."
  };
};

const overlapsSectionData = (pe: PeWindowsParseResult, start: number, size: number): boolean =>
  pe.sections.some(section => section.sizeOfRawData > 0 &&
    start < section.pointerToRawData + section.sizeOfRawData &&
    start + size > section.pointerToRawData);

export const getDebugStorageInfo = (
  pe: PeWindowsParseResult,
  entry: PeDebugDirectoryEntry
): DebugStorageInfo => {
  if (entry.sizeOfData === 0) {
    return {
      label: "NO PAYLOAD",
      description: "SizeOfData is zero; this debug entry has no payload to locate."
    };
  }
  if (entry.pointerToRawData && entry.sizeOfData > pe.fileSize - entry.pointerToRawData) {
    return {
      label: "UNRESOLVED",
      description: "The payload range at the file pointer exceeds the file bounds."
    };
  }
  if (entry.addressOfRawData) return getRvaStorageInfo(pe, entry);
  if (!entry.pointerToRawData) return UNRESOLVED_STORAGE;
  if (overlapsSectionData(pe, entry.pointerToRawData, entry.sizeOfData)) {
    return {
      label: "INCONSISTENT",
      description: "The file range overlaps section data, but the entry supplies no RVA."
    };
  }
  return {
    label: "UNMAPPED",
    description: "The file pointer locates the payload outside section data, and the entry supplies no RVA."
  };
};

const formatDebugCount = (count: number, label: string): string =>
  `${count} ${label}${count === 1 ? "" : "s"}`;

const embeddedPdbSummary = (entry: PeDebugDirectoryEntry): string | null => {
  if (!entry.embeddedPortablePdb) return null;
  const pdb = entry.embeddedPortablePdb.portablePdb;
  return pdb ? `Embedded Portable PDB: ${formatDebugCount(pdb.documents.length, "source document")}, ` +
    `${formatDebugCount(pdb.methodsWithSequencePoints, "method")} with source mappings.`
    : "Embedded Portable PDB header; debug metadata was not decoded.";
};

const payloadSummaries: ReadonlyArray<(entry: PeDebugDirectoryEntry) => string | null> = [
  entry => entry.td32 ? `Borland TD32 ${entry.td32.signature}: names, modules, symbols and source mappings.` : null,
  entry => entry.coff
    ? `COFF symbol table with ${formatDebugCount(entry.coff.symbols.length, "parsed primary symbol")}.` : null,
  entry => entry.codeView ? `CodeView ${entry.codeView.signature} record with PDB identity and path.` : null,
  entry => entry.legacyCodeView ? `Embedded ${entry.legacyCodeView.signature} CodeView: ` +
    `modules, symbols, source mappings and type records.` : null,
  entry => entry.fpo
    ? `Frame-pointer omission table with ${formatDebugCount(entry.fpo.records.length, "record")}.` : null,
  entry => entry.fixup ? `Link-time relocation metadata with ${formatDebugCount(entry.fixup.records.length, "fixup")}.` : null,
  entry => entry.misc ? `Legacy DBG-file locations: ` +
    `${formatDebugCount(entry.misc.records.filter(record => record.text).length, "decoded path")} in ` +
    `${formatDebugCount(entry.misc.records.length, "MISC record")}.` : null,
  entry => entry.omap ? `Address map with ${formatDebugCount(entry.omap.records.length, "record")}.` : null,
  entry => entry.vcFeature ? "MSVC toolchain counters such as /GS, /sdl, and guardN." : null,
  entry => entry.mpx ? "Intel MPX configuration: enablement, runtime support and bounds-violation handling." : null,
  entry => entry.spgo ? "SPGO UTF-16 text metadata." : null,
  entry => entry.pogo ? `Linker layout map with ${formatDebugCount(entry.pogo.entries.length, "record")}.` : null,
  entry => entry.repro ? "Deterministic build marker." : null,
  embeddedPdbSummary,
  entry => entry.pdbChecksum ? `${entry.pdbChecksum.algorithmName || "PDB"} checksum.` : null,
  entry => entry.exDllCharacteristics ? "Extended DLL characteristics bit field." : null,
  entry => entry.r2rPerfMap ? `ReadyToRun PerfMap pointer to ${entry.r2rPerfMap.path || "(no path)"}.` : null,
  entry => entry.rawPayload
    ? "Payload format is unsupported or malformed; no semantic decoding is available." : null
];

export const getEntrySummary = (entry: PeDebugDirectoryEntry): string => {
  if (entry.type === IMAGE_DEBUG_TYPE_ILTCG) {
    return getDebugTypeInfo(entry.type).description +
      (entry.sizeOfData === 0 ? " This entry has no payload." : " Payload format is not documented here.");
  }
  for (const summary of payloadSummaries) {
    const text = summary(entry);
    if (text) return text;
  }
  return getDebugTypeInfo(entry.type >>> 0).description;
};
