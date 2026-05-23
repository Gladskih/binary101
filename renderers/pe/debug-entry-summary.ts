"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
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
  const rawRange = getDebugRawRange(pe, entry);
  if (!rawRange) {
    return {
      label: "UNRESOLVED",
      description: "Payload size is zero or the raw data location does not resolve to a file range."
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

const formatPogoRecordCount = (count: number): string =>
  `${count} record${count === 1 ? "" : "s"}`;

export const getEntrySummary = (entry: PeDebugDirectoryEntry): string => {
  if (entry.codeView) {
    return entry.codeView.signature === "NB10"
      ? "CodeView NB10 record with PDB identity and path."
      : "CodeView RSDS record with PDB identity and path.";
  }
  if (entry.fpo) return `Frame-pointer omission table with ${entry.fpo.records.length} records.`;
  if (entry.misc) return "Legacy DBG-file location record.";
  if (entry.vcFeature) return "MSVC toolchain counters such as /GS, /sdl, and guardN.";
  if (entry.pogo) {
    return `${entry.pogo.signatureName} profile-guided optimization map with ` +
      `${formatPogoRecordCount(entry.pogo.entries.length)}.`;
  }
  if (entry.repro) return "Deterministic build marker.";
  if (entry.embeddedPortablePdb) return "Deflate-compressed Portable PDB embedded in the PE file.";
  if (entry.pdbChecksum) return `${entry.pdbChecksum.algorithmName || "PDB"} checksum.`;
  if (entry.exDllCharacteristics) return "Extended DLL characteristics bit field.";
  if (entry.rawPayload) return "Raw debug payload preview for a reserved or unrecognized format.";
  return getDebugTypeInfo(entry.type >>> 0).description;
};
