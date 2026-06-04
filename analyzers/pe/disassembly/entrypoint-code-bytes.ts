"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { peSectionNameValue } from "../sections/name.js";
import type { PeSection } from "../types.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "./types.js";
import { IMAGE_SCN_MEM_EXECUTE, RVA_EXCLUSIVE_LIMIT, getHeaderRvaLimit } from "./entrypoint-metadata.js";

export type MappedCodeBlock = {
  fileOffsetStart: number;
  rvaStart: number;
  data: Uint8Array<ArrayBufferLike>;
};

const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = getMappedSectionSpan(section);
    const end = Math.min(RVA_EXCLUSIVE_LIMIT, start + size);
    if (rva >= start && rva < end) return section;
  }
  return null;
};

const loadSectionCodeBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  section: PeSection,
  rva: number,
  issues: string[],
  subject: string
): Promise<MappedCodeBlock | null> => {
  const sectionRva = section.virtualAddress >>> 0;
  const offsetInSection = rva - sectionRva;
  const mappedAvailable = getMappedSectionSpan(section) - offsetInSection;
  const fileOffsetStart = opts.rvaToOff(rva);
  const rawStart = section.pointerToRawData >>> 0;
  const rawEnd = rawStart + (section.sizeOfRawData >>> 0);
  if (
    fileOffsetStart == null ||
    !Number.isSafeInteger(fileOffsetStart) ||
    fileOffsetStart < rawStart ||
    fileOffsetStart >= rawEnd ||
    mappedAvailable <= 0
  ) {
    issues.push(`${subject} maps outside the section bytes stored in the file.`);
    return null;
  }
  const rawAvailable = rawEnd - fileOffsetStart;
  const readableSize = Math.min(mappedAvailable, rawAvailable, reader.size - fileOffsetStart);
  if (readableSize <= 0) {
    issues.push(`No file bytes are available at the mapped ${subject.toLowerCase()}.`);
    return null;
  }
  return {
    fileOffsetStart,
    rvaStart: rva >>> 0,
    data: await reader.readBytes(fileOffsetStart, readableSize)
  };
};

const loadHeaderCodeBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  rva: number,
  issues: string[],
  subject: string
): Promise<MappedCodeBlock | null> => {
  const headerRvaLimit = getHeaderRvaLimit(opts);
  if (headerRvaLimit <= rva) {
    issues.push(`${subject} is not inside a section or the mapped PE headers.`);
    return null;
  }
  const fileOffsetStart = opts.rvaToOff(rva);
  if (
    fileOffsetStart == null ||
    !Number.isSafeInteger(fileOffsetStart) ||
    fileOffsetStart < 0 ||
    fileOffsetStart >= reader.size
  ) {
    issues.push(`${subject} RVA could not be mapped to a file offset.`);
    return null;
  }
  // Microsoft PE format: header-resident entrypoints are mapped only through SizeOfHeaders.
  const readableSize = Math.min(headerRvaLimit - rva, reader.size - fileOffsetStart);
  return {
    fileOffsetStart,
    rvaStart: rva >>> 0,
    data: await reader.readBytes(fileOffsetStart, readableSize)
  };
};

export const loadCodeBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  rva: number,
  issues: string[],
  subject: string
): Promise<MappedCodeBlock | null> => {
  const section = findSectionContainingRva(opts.sections, rva);
  if (!section) return loadHeaderCodeBytes(reader, opts, rva, issues, subject);
  if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0) {
    issues.push(
      `${subject} is inside non-executable section ${peSectionNameValue(section.name)}; not followed.`
    );
    return null;
  }
  return loadSectionCodeBytes(reader, opts, section, rva, issues, subject);
};
