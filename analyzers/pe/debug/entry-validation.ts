import type { PeDebugDirectoryEntry } from "./directory.js";
import type { RvaToOffset } from "../types.js";

const validateVersionOne = (entry: PeDebugDirectoryEntry, warnings: string[]): void => {
  if (entry.majorVersion !== 1 || entry.minorVersion !== 0) {
    warnings.push(`${entry.typeName} debug entry has an unsupported directory version.`);
  }
};

const validatePortableCodeView = (entry: PeDebugDirectoryEntry, warnings: string[]): void => {
  if (entry.codeView?.signature !== "RSDS" || entry.codeView.age !== 1) {
    warnings.push("Portable CodeView requires an RSDS record with PDB age 1.");
  }
};

const validateVersions = (entry: PeDebugDirectoryEntry, warnings: string[]): void => {
  // Version contracts: .NET PE/COFF Specification Addendum, debug entries 2, 17, 19, 21.
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
  if (entry.type === 2 && entry.minorVersion === 0x504d) validatePortableCodeView(entry, warnings);
  if (entry.type === 17 && (entry.minorVersion !== 0x0100 || entry.timeDateStamp !== 0)) {
    warnings.push("Embedded Portable PDB requires minor version 0x0100 and a zero timestamp.");
  }
  if (entry.type === 19 || entry.type === 21) validateVersionOne(entry, warnings);
};

const validateLocations = (
  entry: PeDebugDirectoryEntry, rvaToOff: RvaToOffset, fileSize: number, warnings: string[]
): void => {
  if (entry.sizeOfData === 0) return;
  if (entry.pointerToRawData && entry.addressOfRawData &&
      rvaToOff(entry.addressOfRawData) !== entry.pointerToRawData) {
    warnings.push("Debug AddressOfRawData and PointerToRawData disagree; using the file pointer.");
  }
  if (entry.pointerToRawData && (entry.pointerToRawData > fileSize ||
      entry.sizeOfData > fileSize - entry.pointerToRawData)) {
    warnings.push("Debug payload file range exceeds the file bounds.");
  }
};

export const validateDebugEntry = (
  entry: PeDebugDirectoryEntry, rvaToOff: RvaToOffset, fileSize: number
): string[] => {
  const warnings: string[] = [];
  validateVersions(entry, warnings);
  validateLocations(entry, rvaToOff, fileSize, warnings);
  if (entry.rawPayload || (entry.sizeOfData &&
      ![1, 2, 3, 4, 5, 6, 7, 8, 12, 13, 16, 17, 18, 19, 20, 21].includes(entry.type))) {
    warnings.push(`${entry.typeName} payload is not decoded; the format is unsupported or malformed.`);
  }
  return warnings;
};

export const validatePortablePdbLinks = (entries: PeDebugDirectoryEntry[]): string[] => {
  const codeViews = entries.filter(entry => entry.type === 2 && entry.minorVersion === 0x504d);
  if (!codeViews.length) return [];
  return entries.flatMap(entry => {
    const pdb = entry.embeddedPortablePdb?.portablePdb;
    if (!pdb) return [];
    const match = codeViews.some(candidate => candidate.codeView?.signature === "RSDS" &&
      candidate.codeView.guid.toLowerCase() === pdb.id.guid && candidate.timeDateStamp === pdb.id.stamp);
    return match ? [] : ["Embedded Portable PDB identity does not match any portable CodeView entry."];
  });
};
