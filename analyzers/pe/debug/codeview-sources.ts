import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeSection, PeDataDirectory, RvaToOffset } from "../types.js";
import { peSectionNameValue } from "../sections/name.js";
import { contiguousRvaOffset } from "../rva-mapping.js";
import type { PeDebugDirectoryEntry } from "./directory.js";
import { directHllDirectory, findCodeViewLocation, type CodeViewLocation } from "./codeview-location.js";
import { decodeCodeViewPayload } from "./codeview-payload.js";
import type { PeLegacyCodeViewInfo } from "./legacy-codeview.js";

export interface PeCodeViewSource extends CodeViewLocation {
  kind: "section" | "overlay" | "directory";
  legacyCodeView: PeLegacyCodeViewInfo;
}
type Candidate = CodeViewLocation & { kind: PeCodeViewSource["kind"] };

const candidates = (reader: FileRangeReader, sections: readonly PeSection[], headersSize: number): Candidate[] => {
  const ranges: Candidate[] = sections.filter(section => peSectionNameValue(section.name) === ".debug")
    .map(section => ({ kind: "section", offset: section.pointerToRawData, size: section.sizeOfRawData }));
  const imageEnd = sections.reduce((end, section) =>
    Math.max(end, section.pointerToRawData + section.sizeOfRawData), headersSize);
  if (imageEnd < reader.size) ranges.push({ kind: "overlay", offset: imageEnd, size: reader.size - imageEnd });
  return ranges;
};

const alreadyDecoded = (location: CodeViewLocation, entries: readonly PeDebugDirectoryEntry[],
  rvaToOff: RvaToOffset, size: number): boolean => entries.some(entry => {
  if (!entry.legacyCodeView) return false;
  const start = entry.pointerToRawData || contiguousRvaOffset(rvaToOff, entry.addressOfRawData, entry.sizeOfData, size);
  return start != null && start <= location.offset && start + entry.sizeOfData === location.offset + location.size;
});

export const parseCodeViewSources = async (reader: FileRangeReader, sections: readonly PeSection[],
  headersSize: number, entries: readonly PeDebugDirectoryEntry[], directories: readonly PeDataDirectory[],
  rvaToOff: RvaToOffset, warn: (message: string) => void): Promise<PeCodeViewSource[]> => {
  const ranges = candidates(reader, sections, headersSize);
  const directory = directories.find(entry => entry.name === "DEBUG");
  if (directory) {
    const direct = await directHllDirectory(reader, directory, rvaToOff, warn);
    if (direct) ranges.unshift({ ...direct, kind: "directory" });
  }
  const sources: PeCodeViewSource[] = [];
  const seen = new Set<string>();
  for (const candidate of ranges) {
    const key = `range:${candidate.offset}:${candidate.size}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const location = await findCodeViewLocation(reader, candidate.offset, candidate.size, warn);
    if (!location) continue;
    const decodedKey = `decoded:${location.offset}:${location.size}`;
    if (seen.has(decodedKey) || alreadyDecoded(location, entries, rvaToOff, reader.size)) continue;
    seen.add(decodedKey);
    const decoded = await decodeCodeViewPayload(reader, reader.size, rvaToOff, 0, location.offset, location.size, warn);
    if (decoded.legacyCodeView) sources.push({ ...location, kind: candidate.kind,
      legacyCodeView: decoded.legacyCodeView });
  }
  return sources;
};
