"use strict";

import { addSectionEntropies } from "./entropy.js";
import { buildCoverage } from "./coverage.js";
import { peProbe } from "./signature.js";
import { computeEntrySection } from "./core-entry.js";
import {
  parseCoffHeader,
  parseDosHeaderAndStub,
  parseOptionalHeaderAndDirectories,
  parseSectionHeaders
} from "./core-headers.js";
import type { PeCore } from "./types.js";

export async function parsePeHeaders(file: File): Promise<PeCore | null> {
  const head = new DataView(await file.slice(0, Math.min(file.size, 0x400)).arrayBuffer());
  const probe = peProbe(head);
  if (!probe) return null;
  const e_lfanew = probe.e_lfanew;
  if (e_lfanew == null || e_lfanew + 24 > file.size) return null;

  const dos = await parseDosHeaderAndStub(file, head, e_lfanew);
  const coff = await parseCoffHeader(file, e_lfanew);
  if (!coff) return null;

  const { optOff, ddStartRel, ddCount, dataDirs, opt } = await parseOptionalHeaderAndDirectories(
    file,
    e_lfanew,
    coff.SizeOfOptionalHeader
  );
  const { sections, rvaToOff, sectOff } = await parseSectionHeaders(
    file,
    optOff,
    coff.SizeOfOptionalHeader,
    coff.NumberOfSections
  );

  const { coverage, addCov, overlaySize, imageEnd, imageSizeMismatch } = buildCoverage(
    file.size,
    e_lfanew,
    coff,
    optOff,
    ddStartRel,
    ddCount,
    sectOff,
    sections,
    opt.SectionAlignment,
    opt.SizeOfImage
  );

  await addSectionEntropies(file, sections);
  const entrySection = await computeEntrySection(opt, sections);

  return {
    dos,
    coff,
    opt,
    dataDirs,
    sections,
    entrySection,
    rvaToOff,
    coverage,
    addCoverageRegion: addCov,
    overlaySize,
    imageEnd,
    imageSizeMismatch
  };
}
