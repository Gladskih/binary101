"use strict";

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

const countTrailingZeroBytes = async (file: File): Promise<number> => {
  let zeroCount = 0;
  let end = file.size;
  while (end > 0) {
    const start = Math.max(0, end - ZERO_SCAN_CHUNK_SIZE);
    const chunk = new Uint8Array(await file.slice(start, end).arrayBuffer());
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
  file: File,
  fileAlignment: number
): Promise<number> => {
  const normalizedAlignment = fileAlignment >>> 0;
  if (!normalizedAlignment) return 0;
  const trailingZeroBytes = await countTrailingZeroBytes(file);
  if (!trailingZeroBytes) return 0;
  const dataEnd = file.size - trailingZeroBytes;
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
  file: File,
  dos: PeCore["dos"],
  coff: PeCore["coff"],
  optionalHeaderResult: Awaited<ReturnType<typeof parseOptionalHeaderAndDirectories>>,
  opt: PeHeaderCore["opt"]
): Promise<PeHeaderCore> => {
  const parsedSections = await parseSectionHeaders(
    file,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    coff.NumberOfSections,
    0,
    coff.PointerToSymbolTable,
    coff.NumberOfSymbols
  );
  const { overlaySize, imageEnd, imageSizeMismatch } = computePeImageLayout(
    file.size,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    parsedSections.sectOff,
    coff.NumberOfSections,
    parsedSections.sections,
    0,
    null,
    0
  );
  await addSectionEntropies(file, parsedSections.sections);
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
  file: File,
  dos: PeCore["dos"],
  coff: PeCore["coff"],
  optionalHeaderResult: Awaited<ReturnType<typeof parseOptionalHeaderAndDirectories>>,
  opt: PeWindowsOptionalHeader
): Promise<PeWindowsCore> => {
  const parsedSections = await parseSectionHeaders(
    file,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    coff.NumberOfSections,
    opt.SizeOfHeaders,
    coff.PointerToSymbolTable,
    coff.NumberOfSymbols
  );
  const { overlaySize, imageEnd, imageSizeMismatch } = computePeImageLayout(
    file.size,
    optionalHeaderResult.optOff,
    coff.SizeOfOptionalHeader,
    parsedSections.sectOff,
    coff.NumberOfSections,
    parsedSections.sections,
    opt.SectionAlignment,
    opt.SizeOfImage,
    opt.SizeOfHeaders
  );
  await addSectionEntropies(file, parsedSections.sections);
  const trailingAlignmentPaddingSize = await computeTrailingAlignmentPaddingSize(file, opt.FileAlignment);
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

export async function parsePeHeaders(file: File): Promise<PeCore | null> {
  const head = new DataView(await file.slice(0, Math.min(file.size, 0x400)).arrayBuffer());
  const probe = peProbe(head);
  if (!probe) return null;
  const e_lfanew = probe.e_lfanew;
  if (e_lfanew == null || e_lfanew + 4 > file.size) return null;

  const dos = await parseDosHeaderAndStub(file, head, e_lfanew);
  const coff = await parseCoffHeader(file, e_lfanew);
  if (!coff) return null;

  const optionalResult = await parseOptionalHeaderAndDirectories(file, e_lfanew, coff.SizeOfOptionalHeader);
  return optionalResult.opt && optionalResult.opt.Magic !== ROM_OPTIONAL_HEADER_MAGIC
    ? buildWindowsCore(file, dos, coff, optionalResult, optionalResult.opt)
    : buildHeaderCore(file, dos, coff, optionalResult, optionalResult.opt);
}
