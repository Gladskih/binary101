"use strict";

import { addSectionEntropies } from "./entropy.js";
import { isPeWindowsOptionalHeader } from "./optional-header-kind.js";
import { peProbe } from "./signature.js";
import { computeEntrySection } from "./core-entry.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./rva-limits.js";
import {
  parseCoffHeader,
  parseDosHeaderAndStub,
  parseOptionalHeaderAndDirectories
} from "./core-headers.js";
import { parseSectionHeaders } from "./sections.js";
import type { PeCore } from "./types.js";

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

const computePeImageLayout = (
  fileSize: number,
  optionalHeaderOffset: number,
  optionalHeaderSize: number,
  sectionHeadersOffset: number,
  sectionCount: number,
  sections: PeCore["sections"],
  sectionAlignment: number,
  sizeOfImage: number,
  declaredSizeOfHeaders: number,
  hasDeclaredSizeOfImage: boolean
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
    imageSizeMismatch: hasDeclaredSizeOfImage && imageEnd !== (sizeOfImage >>> 0)
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
  const { optOff, ddStartRel, ddCount, dataDirs, opt } = optionalResult;
  const windowsOpt = isPeWindowsOptionalHeader(opt) ? opt : null;
  const { sections, rvaToOff, sectOff, warnings: sectionWarnings } = await parseSectionHeaders(
    file,
    optOff,
    coff.SizeOfOptionalHeader,
    coff.NumberOfSections,
    windowsOpt?.SizeOfHeaders ?? 0,
    coff.PointerToSymbolTable,
    coff.NumberOfSymbols
  );
  const { overlaySize, imageEnd, imageSizeMismatch } = computePeImageLayout(
    file.size,
    optOff,
    coff.SizeOfOptionalHeader,
    sectOff,
    coff.NumberOfSections,
    sections,
    windowsOpt?.SectionAlignment ?? 0,
    windowsOpt?.SizeOfImage ?? 0,
    windowsOpt?.SizeOfHeaders ?? 0,
    !!windowsOpt
  );

  await addSectionEntropies(file, sections);
  const entrySection = await computeEntrySection(opt, sections);
  const warnings = mergeWarnings(optionalResult.warnings, sectionWarnings);

  return {
    dos,
    coff,
    opt,
    ...(warnings ? { warnings } : {}),
    optOff,
    ddStartRel,
    ddCount,
    dataDirs,
    sections,
    entrySection,
    rvaToOff,
    overlaySize,
    imageEnd,
    imageSizeMismatch
  };
}
