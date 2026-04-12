"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { addSectionEntropies } from "./entropy.js";
import {
  ROM_OPTIONAL_HEADER_MAGIC
} from "./optional-header-magic.js";
import { peProbe } from "./signature.js";
import { computeEntrySection } from "./core-entry.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./rva-limits.js";
import {
  parseCoffHeader,
  parseDosHeaderAndStub,
  parseOptionalHeaderAndDirectories
} from "./core-headers.js";
import { parseSectionHeaders } from "./sections.js";
import type { PeCore, PeHeaderCore, PeWindowsCore, PeWindowsOptionalHeader } from "./types.js";

const mergeWarnings = (...groups: Array<string[] | undefined>): string[] | undefined => {
  const merged = new Set(groups.flatMap(group => group ?? []));
  return merged.size ? [...merged] : undefined;
};

const alignUpClamped = (value: number, alignment: number): number => {
  const normalizedValue = Math.max(0, value);
  const normalizedAlignment = alignment >>> 0;
  if (!normalizedAlignment) return Math.min(PE_RVA_EXCLUSIVE_LIMIT, normalizedValue);
  const remainder = normalizedValue % normalizedAlignment;
  const aligned = remainder === 0 ? normalizedValue : normalizedValue + normalizedAlignment - remainder;
  return Math.min(PE_RVA_EXCLUSIVE_LIMIT, aligned);
};

const ZERO_SCAN_CHUNK_SIZE = 4096;

const countTrailingZeroBytes = async (reader: FileRangeReader): Promise<number> => {
  let zeroCount = 0;
  let end = reader.size;
  while (end > 0) {
    const start = Math.max(0, end - ZERO_SCAN_CHUNK_SIZE);
    const chunk = await reader.readBytes(start, end - start);
    if (!chunk.length) break;
    for (let index = chunk.length - 1; index >= 0; index -= 1) {
      if (chunk[index] !== 0) {
        return zeroCount + (chunk.length - 1 - index);
      }
    }
    zeroCount += chunk.length;
    end = start;
  }
  return zeroCount;
};

const computeTrailingAlignmentPaddingSize = async (
  reader: FileRangeReader,
  fileAlignment: number
): Promise<number> => {
  const normalizedAlignment = fileAlignment >>> 0;
  if (!normalizedAlignment) return 0;
  const trailingZeroBytes = await countTrailingZeroBytes(reader);
  if (!trailingZeroBytes) return 0;
  const dataEnd = reader.size - trailingZeroBytes;
  const remainder = dataEnd % normalizedAlignment;
  const expectedPadding = remainder === 0 ? 0 : normalizedAlignment - remainder;
  return expectedPadding === trailingZeroBytes ? expectedPadding : 0;
};

const computePeImageLayout = (
  fileSize: number,
  optionalHeaderOffset: number,
  optionalHeaderSize: number,
  sectionHeadersOffset: number,
  sectionCount: number,
  sections: PeCore["sections"],
  sectionAlignment: number,
  declaredSizeOfImage: number | null,
  declaredSizeOfHeaders: number
): {
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
} => {
  const headersEnd = Math.max(
    optionalHeaderOffset + optionalHeaderSize,
    sectionHeadersOffset + sectionCount * 40
  );
  const normalizedSizeOfHeaders =
    Number.isSafeInteger(declaredSizeOfHeaders) && declaredSizeOfHeaders > 0
      ? Math.min(fileSize, declaredSizeOfHeaders >>> 0)
      : headersEnd;
  let rawEnd = Math.max(headersEnd, normalizedSizeOfHeaders);
  for (const section of sections) {
    const endOfSectionData = (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0);
    rawEnd = Math.max(rawEnd, endOfSectionData);
  }
  const overlaySize = fileSize > rawEnd ? fileSize - rawEnd : 0;
  let imageEnd = alignUpClamped(Math.max(headersEnd, normalizedSizeOfHeaders), sectionAlignment);
  for (const section of sections) {
    const endOfSectionImage = Math.min(
      PE_RVA_EXCLUSIVE_LIMIT,
      (section.virtualAddress >>> 0) + ((section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0))
    );
    imageEnd = Math.max(imageEnd, alignUpClamped(endOfSectionImage, sectionAlignment));
  }
  return {
    overlaySize,
    imageEnd,
    imageSizeMismatch: declaredSizeOfImage != null && imageEnd !== (declaredSizeOfImage >>> 0)
  };
};

const buildCoreWarnings = (
  optionalHeaderWarnings: string[] | undefined,
  sectionWarnings: string[] | undefined
): string[] | undefined => mergeWarnings(optionalHeaderWarnings, sectionWarnings);

export const isPeWindowsCore = (core: PeCore): core is PeWindowsCore =>
  core.opt != null && core.opt.Magic !== ROM_OPTIONAL_HEADER_MAGIC;

const buildHeaderCore = async (
  reader: FileRangeReader,
  dos: PeCore["dos"],
  coff: PeCore["coff"],
  optionalHeaderResult: Awaited<ReturnType<typeof parseOptionalHeaderAndDirectories>>,
  opt: PeHeaderCore["opt"]
): Promise<PeHeaderCore> => {
  const parsedSections = await parseSectionHeaders(
    reader,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    coff.NumberOfSections,
    0,
    coff.PointerToSymbolTable,
    coff.NumberOfSymbols
  );
  const { overlaySize, imageEnd, imageSizeMismatch } = computePeImageLayout(
    reader.size,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    parsedSections.sectOff,
    coff.NumberOfSections,
    parsedSections.sections,
    0,
    null,
    0
  );
  await addSectionEntropies(reader, parsedSections.sections);
  const warnings = buildCoreWarnings(optionalHeaderResult.warnings, parsedSections.warnings);
  return {
    dos,
    coff,
    ...(parsedSections.coffStringTableSize != null
      ? { coffStringTableSize: parsedSections.coffStringTableSize }
      : {}),
    opt,
    ...(warnings ? { warnings } : {}),
    optOff: optionalHeaderResult.optOff,
    ddStartRel: optionalHeaderResult.ddStartRel,
    ddCount: optionalHeaderResult.ddCount,
    dataDirs: [],
    sections: parsedSections.sections,
    entrySection: await computeEntrySection(optionalHeaderResult.opt, parsedSections.sections),
    rvaToOff: parsedSections.rvaToOff,
    overlaySize,
    imageEnd,
    imageSizeMismatch
  };
};

const buildWindowsCore = async (
  reader: FileRangeReader,
  dos: PeCore["dos"],
  coff: PeCore["coff"],
  optionalHeaderResult: Awaited<ReturnType<typeof parseOptionalHeaderAndDirectories>>,
  opt: PeWindowsOptionalHeader
): Promise<PeWindowsCore> => {
  const parsedSections = await parseSectionHeaders(
    reader,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    coff.NumberOfSections,
    opt.SizeOfHeaders,
    coff.PointerToSymbolTable,
    coff.NumberOfSymbols
  );
  const { overlaySize, imageEnd, imageSizeMismatch } = computePeImageLayout(
    reader.size,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    parsedSections.sectOff,
    coff.NumberOfSections,
    parsedSections.sections,
    opt.SectionAlignment,
    opt.SizeOfImage,
    opt.SizeOfHeaders
  );
  await addSectionEntropies(reader, parsedSections.sections);
  const trailingAlignmentPaddingSize = await computeTrailingAlignmentPaddingSize(reader, opt.FileAlignment);
  const warnings = buildCoreWarnings(optionalHeaderResult.warnings, parsedSections.warnings);
  return {
    dos,
    coff,
    ...(parsedSections.coffStringTableSize != null
      ? { coffStringTableSize: parsedSections.coffStringTableSize }
      : {}),
    ...(trailingAlignmentPaddingSize ? { trailingAlignmentPaddingSize } : {}),
    opt,
    ...(warnings ? { warnings } : {}),
    optOff: optionalHeaderResult.optOff,
    ddStartRel: optionalHeaderResult.ddStartRel,
    ddCount: optionalHeaderResult.ddCount,
    dataDirs: optionalHeaderResult.dataDirs,
    sections: parsedSections.sections,
    entrySection: await computeEntrySection(opt, parsedSections.sections),
    rvaToOff: parsedSections.rvaToOff,
    overlaySize,
    imageEnd,
    imageSizeMismatch
  };
};

export async function parsePeHeaders(reader: FileRangeReader): Promise<PeCore | null> {
  const head = await reader.read(0, Math.min(reader.size, 0x400));
  const probe = peProbe(head);
  if (!probe) return null;
  const e_lfanew = probe.e_lfanew;
  if (e_lfanew == null || e_lfanew + 4 > reader.size) return null;

  const dos = await parseDosHeaderAndStub(reader, head, e_lfanew);
  const coff = await parseCoffHeader(reader, e_lfanew);
  if (!coff) return null;

  const optionalResult = await parseOptionalHeaderAndDirectories(
    reader,
    e_lfanew,
    coff.SizeOfOptionalHeader
  );
  return optionalResult.opt && optionalResult.opt.Magic !== ROM_OPTIONAL_HEADER_MAGIC
    ? buildWindowsCore(reader, dos, coff, optionalResult, optionalResult.opt)
    : buildHeaderCore(reader, dos, coff, optionalResult, optionalResult.opt);
}
