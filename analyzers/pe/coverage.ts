"use strict";

import { alignUpTo } from "../../binary-utils.js";
import type {
  AddCoverageRegion,
  PeCoffHeader,
  PeCoverageEntry,
  PeSection
} from "./types.js";

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
  sizeOfImage: number
): {
  coverage: PeCoverageEntry[];
  addCov: AddCoverageRegion;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
  } {
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
  let rawEnd = 0;
  for (const section of sections) {
    const endOfSectionData = (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0);
    rawEnd = Math.max(rawEnd, endOfSectionData);
  }
  const overlaySize = fileSize > rawEnd ? fileSize - rawEnd : 0;
  let imageEnd = 0;
  for (const section of sections) {
    const endOfSectionImage = (section.virtualAddress >>> 0) + (section.virtualSize >>> 0);
    imageEnd = Math.max(imageEnd, alignUpTo(endOfSectionImage, sectionAlignment >>> 0));
  }
  const imageSizeMismatch = imageEnd !== (sizeOfImage >>> 0);
  if (overlaySize > 0) addCov("Overlay (data after last section)", rawEnd, overlaySize);
  for (const section of sections) {
    addCov(`Section ${section.name} (raw)`, section.pointerToRawData, section.sizeOfRawData);
  }
  return { coverage, addCov, overlaySize, imageEnd, imageSizeMismatch };
}
