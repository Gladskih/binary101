"use strict";
import type {
  AddCoverageRegion,
  PeCoffHeader,
  PeCoverageEntry,
  PeSection
} from "./types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./rva-limits.js";

export function buildCoverage(
  fileSize: number,
  peHeaderOffset: number,
  coff: PeCoffHeader,
  optionalHeaderOffset: number,
  optionalHeaderSize: number,
  ddStartRel: number,
  ddCount: number,
  sectionHeadersOffset: number,
  sections: PeSection[],
  sectionAlignment: number,
  sizeOfImage: number,
  declaredSizeOfHeaders = 0
): {
  coverage: PeCoverageEntry[];
  addCov: AddCoverageRegion;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
} {
  const alignUpClamped = (value: number, alignment: number): number => {
    const normalizedValue = Math.max(0, value);
    const normalizedAlignment = alignment >>> 0;
    if (!normalizedAlignment) return Math.min(PE_RVA_EXCLUSIVE_LIMIT, normalizedValue);
    const remainder = normalizedValue % normalizedAlignment;
    const aligned = remainder === 0 ? normalizedValue : normalizedValue + normalizedAlignment - remainder;
    return Math.min(PE_RVA_EXCLUSIVE_LIMIT, aligned);
  };
  const coverage: PeCoverageEntry[] = [];
  const addCov: AddCoverageRegion = (label, off, size) => {
    if (!Number.isFinite(off) || !Number.isFinite(size) || off < 0 || size <= 0) return;
    coverage.push({ label, off: off >>> 0, end: (off >>> 0) + (size >>> 0), size: size >>> 0 });
  };
  addCov("DOS header + stub", 0, Math.min(fileSize, Math.max(64, peHeaderOffset)));
  addCov("PE signature + COFF", peHeaderOffset, 24);
  addCov("Optional header", optionalHeaderOffset, optionalHeaderSize);
  addCov("Data directories", optionalHeaderOffset + ddStartRel, ddCount * 8);
  addCov("Section headers", sectionHeadersOffset, coff.NumberOfSections * 40);
  const headersEnd = Math.max(
    optionalHeaderOffset + optionalHeaderSize,
    sectionHeadersOffset + coff.NumberOfSections * 40
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
  const imageSizeMismatch = imageEnd !== (sizeOfImage >>> 0);
  if (overlaySize > 0) addCov("Overlay (data after last section)", rawEnd, overlaySize);
  for (const section of sections) {
    addCov(`Section ${section.name} (raw)`, section.pointerToRawData, section.sizeOfRawData);
  }
  return { coverage, addCov, overlaySize, imageEnd, imageSizeMismatch };
}
