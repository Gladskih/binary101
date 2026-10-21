import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeSection, RvaToOffset } from "../types.js";
import type { PeDebugDirectoryEntry } from "./directory.js";
import { contiguousRvaOffset } from "../rva-mapping.js";
import { peSectionNameValue } from "../sections/name.js";
import { findTd32Location, type Td32Location } from "./td32-location.js";
import { parseTd32, type PeTd32Info } from "./td32.js";

export interface PeTd32Source extends Td32Location {
  kind: "section" | "overlay";
  td32: PeTd32Info;
}
type Candidate = Td32Location & { kind: PeTd32Source["kind"] };

const candidates = (reader: FileRangeReader, sections: readonly PeSection[],
  headersSize: number): Candidate[] => {
  const ranges: Candidate[] = sections.filter(section => peSectionNameValue(section.name) === ".debug")
    .map(section => ({ kind: "section", offset: section.pointerToRawData, size: section.sizeOfRawData }));
  // This boundary is a file offset, unlike SizeOfImage / core.imageEnd (RVAs).
  const imageEnd = sections.reduce((end, section) =>
    Math.max(end, section.pointerToRawData + section.sizeOfRawData), headersSize);
  if (imageEnd < reader.size) ranges.push({ kind: "overlay", offset: imageEnd, size: reader.size - imageEnd });
  return ranges;
};

const alreadyDecoded = (location: Td32Location, entries: readonly PeDebugDirectoryEntry[],
  rvaToOff: RvaToOffset, fileSize: number): boolean => entries.some(entry => {
  if (!entry.td32) return false;
  const offset = entry.pointerToRawData || contiguousRvaOffset(rvaToOff,
    entry.addressOfRawData, entry.sizeOfData, fileSize);
  // parseTd32 follows the same terminal trailer, even if its payload has a prefix.
  return offset != null && offset <= location.offset &&
    offset + entry.sizeOfData === location.offset + location.size;
});

export const parseTd32Sources = async (reader: FileRangeReader, sections: readonly PeSection[],
  headersSize: number, entries: readonly PeDebugDirectoryEntry[], rvaToOff: RvaToOffset,
  warn: (message: string) => void): Promise<PeTd32Source[]> => {
  const sources: PeTd32Source[] = [];
  const decoded = new Set<string>();
  for (const candidate of candidates(reader, sections, headersSize)) {
    const rangeKey = `range:${candidate.offset}:${candidate.size}`;
    if (decoded.has(rangeKey)) continue;
    decoded.add(rangeKey);
    const location = await findTd32Location(reader, candidate.offset, candidate.size, warn);
    if (!location) continue;
    const key = `td32:${location.offset}:${location.size}`;
    if (decoded.has(key) || alreadyDecoded(location, entries, rvaToOff, reader.size)) continue;
    decoded.add(key);
    const td32 = await parseTd32(reader, reader.size, rvaToOff, 0, location.offset, location.size, warn);
    if (td32) sources.push({ kind: candidate.kind, ...location, td32 });
  }
  return sources;
};
