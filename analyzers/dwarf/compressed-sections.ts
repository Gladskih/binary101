"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  canonicalDwarfSectionName,
  readDwarfCompressionPayload,
  type DwarfCompressionPayload,
  type DwarfSectionCompression
} from "./compression-headers.js";
import { DWARF_SECTION } from "./constants.js";
import type { DwarfSectionInput, DwarfSectionSource } from "./types.js";

export type DwarfSectionCandidate = {
  section: DwarfSectionInput;
  compression: DwarfSectionCompression | null;
};

const supportedNames = new Set<string>([
  DWARF_SECTION.information,
  DWARF_SECTION.lines,
  DWARF_SECTION.types,
  DWARF_SECTION.abbreviations,
  DWARF_SECTION.strings,
  DWARF_SECTION.lineStrings,
  DWARF_SECTION.stringOffsets
]);

const memoryReader = (bytes: Uint8Array): FileRangeReader => {
  const read = async (offset: number, size: number): Promise<DataView> => {
    const start = Math.min(offset, bytes.length);
    const length = Math.max(0, Math.min(size, bytes.length - start));
    return new DataView(bytes.buffer, bytes.byteOffset + start, length);
  };
  const readBytes = async (offset: number, size: number): Promise<Uint8Array> => {
    const view = await read(offset, size);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  };
  return { size: bytes.length, read, readBytes };
};

const inflateZlib = async (
  compressed: Uint8Array,
  expectedSize: number
): Promise<Uint8Array> => {
  if (typeof DecompressionStream !== "function") {
    throw new Error("browser does not provide DecompressionStream");
  }
  const output = new Uint8Array(expectedSize);
  const stream = new Blob([compressed.slice().buffer])
    .stream()
    .pipeThrough(new DecompressionStream("deflate"));
  const streamReader = stream.getReader();
  let offset = 0;
  while (true) {
    const chunk = await streamReader.read();
    if (chunk.done) break;
    if (offset + chunk.value.length > output.length) {
      await streamReader.cancel();
      throw new Error(`output exceeds declared size ${expectedSize}`);
    }
    output.set(chunk.value, offset);
    offset += chunk.value.length;
  }
  if (offset !== output.length) {
    throw new Error(`output size ${offset} does not match declared size ${expectedSize}`);
  }
  return output;
};

const unavailableSource = (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  name: string
): DwarfSectionSource => ({
  summary: section,
  section: { ...section, name },
  reader,
  decoded: false
});

const decodedSource = (
  section: DwarfSectionInput,
  payload: DwarfCompressionPayload,
  bytes: Uint8Array
): DwarfSectionSource => ({
  summary: section,
  section: { name: payload.name, offset: 0, size: bytes.length, compressed: false },
  reader: memoryReader(bytes),
  decoded: true
});

const readCompressedBytes = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  payload: DwarfCompressionPayload,
  issues: string[]
): Promise<Uint8Array | null> => {
  const compressed = await reader.readBytes(payload.offset, payload.size);
  if (compressed.length === payload.size) return compressed;
  issues.push(
    `${section.name}: compressed payload is truncated ` +
    `(${compressed.length} of ${payload.size} bytes readable).`
  );
  return null;
};

const decompressCandidate = async (
  reader: FileRangeReader,
  candidate: DwarfSectionCandidate,
  issues: string[]
): Promise<DwarfSectionSource> => {
  const canonicalName = canonicalDwarfSectionName(candidate.section.name);
  const unavailable = unavailableSource(reader, candidate.section, canonicalName);
  if (candidate.section.requiresRelocations || !supportedNames.has(canonicalName)) {
    return unavailable;
  }
  const payload = await readDwarfCompressionPayload(
    reader,
    candidate.section,
    candidate.compression!,
    issues
  );
  if (!payload) return unavailable;
  const compressed = await readCompressedBytes(reader, candidate.section, payload, issues);
  if (!compressed) return unavailable;
  try {
    const bytes = await inflateZlib(compressed, payload.uncompressedSize);
    return decodedSource(candidate.section, payload, bytes);
  } catch (error) {
    issues.push(
      `${candidate.section.name}: zlib decompression failed: ` +
      `${error instanceof Error ? error.message : String(error)}.`
    );
    return unavailable;
  }
};

const regularSource = (
  reader: FileRangeReader,
  section: DwarfSectionInput
): DwarfSectionSource => ({
  summary: section,
  section,
  reader,
  decoded: !section.requiresRelocations
});

export const prepareDwarfSectionSources = async (
  reader: FileRangeReader,
  candidates: DwarfSectionCandidate[]
): Promise<{ sources: DwarfSectionSource[]; issues: string[] }> => {
  const issues: string[] = [];
  const sources: DwarfSectionSource[] = [];
  for (const candidate of candidates) {
    if (!candidate.compression) {
      sources.push(regularSource(reader, candidate.section));
      continue;
    }
    sources.push(await decompressCandidate(reader, candidate, issues));
  }
  return { sources, issues };
};
