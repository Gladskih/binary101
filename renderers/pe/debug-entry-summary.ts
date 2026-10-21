"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { IMAGE_DEBUG_TYPE_ILTCG } from "../../analyzers/pe/debug/types.js";
import { getDebugTypeInfo } from "./debug-type-info.js";

type DebugStorageInfo = { label: string; description: string };
type FileRange = { start: number; end: number };

const getDebugRawRange = (pe: PeWindowsParseResult, entry: PeDebugDirectoryEntry): FileRange | null => {
  if ((entry.sizeOfData >>> 0) === 0) return null;
  const rawStart = entry.pointerToRawData || (
    entry.addressOfRawData ? pe.rvaToOff(entry.addressOfRawData) : null
  );
  return rawStart == null || rawStart < 0
    ? null
    : { start: rawStart, end: rawStart + (entry.sizeOfData >>> 0) };
};

const isRangeCoveredBySection = (pe: PeWindowsParseResult, range: FileRange): boolean =>
  pe.sections.some(section => {
    const start = section.pointerToRawData >>> 0;
    const end = start + (section.sizeOfRawData >>> 0);
    return range.start >= start && range.end <= end;
  });

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
  const rawRange = getDebugRawRange(pe, entry);
  if (!rawRange) {
    return {
      label: "UNRESOLVED",
      description: "The raw data location does not resolve to a file range."
    };
  }
  const hasRva = (entry.addressOfRawData >>> 0) !== 0;
  const coveredBySection = isRangeCoveredBySection(pe, rawRange);
  if (hasRva && coveredBySection) {
    return {
      label: "MAPPED",
      description: "Payload is section-backed and has a non-zero RVA, so it is mapped into the image."
    };
  }
  if (!hasRva && !coveredBySection) {
    return {
      label: "UNMAPPED",
      description: "Payload is addressed only by file pointer and is not covered by a section header."
    };
  }
  return {
    label: "INCONSISTENT",
    description: "RVA presence and section coverage disagree, so the payload is not cleanly mapped/unmapped."
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
