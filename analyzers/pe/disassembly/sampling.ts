"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { peSectionNameValue } from "../sections/name.js";
import type { PeSection } from "../types.js";
import type { AnalyzePeInstructionSetOptions } from "./types.js";

const IMAGE_SCN_CNT_CODE = 0x00000020; // Microsoft PE format: IMAGE_SCN_CNT_CODE.
const IMAGE_SCN_MEM_EXECUTE = 0x20000000; // Microsoft PE format: IMAGE_SCN_MEM_EXECUTE.

export type PeDisassemblySample = {
  rvaStart: number;
  data: Uint8Array;
};

export const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);

export const isExecutableSection = (section: PeSection): boolean =>
  (section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) !== 0;

export const isMemoryExecutableSection = (section: PeSection): boolean =>
  (section.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;

export const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const end = start + getMappedSectionSpan(section);
    if (rva >= start && rva < end) return section;
  }
  return null;
};

export const findBestCodeSection = (sections: PeSection[]): PeSection | null =>
  sections.find(section => peSectionNameValue(section.name).toLowerCase() === ".text") ||
  sections.find(isExecutableSection) ||
  sections[0] ||
  null;

export const normalizeRvaList = (values: unknown): number[] =>
  uniqueU32s(
    (Array.isArray(values) ? values : []).filter(
      (rva): rva is number => Number.isSafeInteger(rva) && rva > 0
    )
  );

export const uniqueU32s = (values: number[]): number[] => {
  const seen = new Set<number>();
  const out: number[] = [];
  for (const value of values) {
    const normalized = value >>> 0;
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
};

export const resolvePeDisassemblyEntrypoints = (
  opts: AnalyzePeInstructionSetOptions,
  issues: string[]
): number[] => {
  const resolvedEntrypoints: number[] = [];
  const resolvedEntrypointsSet = new Set<number>();
  const firstSectionRva =
    opts.sections.reduce((min, section) => Math.min(min, section.virtualAddress >>> 0), 0xffff_ffff);
  const addEntrypoint = (source: string, rva: number): void => {
    const normalized = rva >>> 0;
    if (resolvedEntrypointsSet.has(normalized)) return;
    const off = opts.rvaToOff(normalized);
    if (off == null) {
      issues.push(`${source} RVA 0x${normalized.toString(16)} could not be mapped to a file offset.`);
      return;
    }
    const containing = findSectionContainingRva(opts.sections, normalized);
    if (containing && !isMemoryExecutableSection(containing)) {
      issues.push(
        `${source} RVA 0x${normalized.toString(16)} points into a non-executable section (` +
        `${peSectionNameValue(containing.name)}; missing IMAGE_SCN_MEM_EXECUTE).`
      );
      return;
    }
    if (!containing && opts.sections.length > 0 && normalized >= firstSectionRva) {
      issues.push(`${source} RVA 0x${normalized.toString(16)} is not within any section.`);
      return;
    }
    resolvedEntrypointsSet.add(normalized);
    resolvedEntrypoints.push(normalized);
  };
  for (const group of createPeEntrypointGroups(opts)) {
    for (const rva of group.rvas) addEntrypoint(group.source, rva);
  }
  if (resolvedEntrypoints.length === 0) addFallbackEntrypoint(opts.sections, resolvedEntrypoints, issues);
  return resolvedEntrypoints;
};

export const collectPeDisassemblySamples = async (
  reader: FileRangeReader,
  opts: AnalyzePeInstructionSetOptions,
  resolvedEntrypoints: number[]
): Promise<PeDisassemblySample[]> =>
  (await Promise.all([
    ...sectionsToSample(opts.sections, resolvedEntrypoints).map(async section => ({
      rvaStart: section.virtualAddress >>> 0,
      data: await loadSectionBytes(reader, section)
    })),
    ...resolvedEntrypoints.map(rva => loadMappedEntrypointBytes(reader, opts, rva))
  ])).filter((entry): entry is PeDisassemblySample => entry != null && entry.data.length > 0);

const createPeEntrypointGroups = (
  opts: AnalyzePeInstructionSetOptions
): Array<{ source: string; rvas: number[] }> => {
  const requestedEntrypointRva =
    Number.isSafeInteger(opts.entrypointRva) && opts.entrypointRva > 0 ? (opts.entrypointRva >>> 0) : 0;
  const groups: Array<{ source: string; rvas: number[] }> = [
    ...(requestedEntrypointRva ? [{ source: "Entry point", rvas: [requestedEntrypointRva] }] : []),
    { source: "Export", rvas: normalizeRvaList(opts.exportRvas) },
    { source: "Unwind", rvas: normalizeRvaList(opts.unwindBeginRvas) },
    { source: "Unwind handler", rvas: normalizeRvaList(opts.unwindHandlerRvas) },
    { source: "GuardCF function", rvas: normalizeRvaList(opts.guardCFFunctionRvas) },
    { source: "SafeSEH handler", rvas: normalizeRvaList(opts.safeSehHandlerRvas) },
    { source: "TLS callback", rvas: normalizeRvaList(opts.tlsCallbackRvas) }
  ];
  for (const entry of Array.isArray(opts.extraEntrypoints) ? opts.extraEntrypoints : []) {
    if (!entry || typeof entry.source !== "string" || !entry.source) continue;
    const rvas = normalizeRvaList(entry.rvas);
    if (rvas.length) groups.push({ source: entry.source, rvas });
  }
  return groups;
};

const addFallbackEntrypoint = (
  sections: PeSection[],
  resolvedEntrypoints: number[],
  issues: string[]
): void => {
  const fallback = findBestCodeSection(sections);
  if (!fallback) {
    issues.push("No section headers available to locate code bytes.");
    return;
  }
  resolvedEntrypoints.push(fallback.virtualAddress >>> 0);
  issues.push(`Falling back to section ${peSectionNameValue(fallback.name) || "(unnamed)"} for disassembly sample.`);
};

const sectionsToSample = (
  sections: PeSection[],
  resolvedEntrypoints: number[]
): PeSection[] =>
  uniqueU32s([
    ...sections.filter(isExecutableSection).map(section => section.virtualAddress >>> 0),
    ...resolvedEntrypoints
      .map(rva => findSectionContainingRva(sections, rva))
      .filter((section): section is PeSection => section != null)
      .map(section => section.virtualAddress >>> 0)
  ])
    .map(rva => findSectionContainingRva(sections, rva))
    .filter((section): section is PeSection => section != null);

const loadSectionBytes = async (
  reader: FileRangeReader,
  section: PeSection
): Promise<Uint8Array> => {
  const start = section.pointerToRawData >>> 0;
  const size = Math.min(section.sizeOfRawData >>> 0, getMappedSectionSpan(section));
  if (!size) return new Uint8Array();
  const end = Math.min(reader.size, start + size);
  if (start >= reader.size || end <= start) return new Uint8Array();
  return reader.readBytes(start, end - start);
};

const loadMappedEntrypointBytes = async (
  reader: FileRangeReader,
  opts: AnalyzePeInstructionSetOptions,
  rva: number
): Promise<PeDisassemblySample | null> => {
  if (findSectionContainingRva(opts.sections, rva)) return null;
  const start = opts.rvaToOff(rva);
  if (start == null || start < 0 || start >= reader.size) return null;
  // Microsoft PE format: header-resident entrypoints are only mapped through SizeOfHeaders.
  const headerRvaLimit =
    Number.isSafeInteger(opts.headerRvaLimit ?? Number.NaN) ? ((opts.headerRvaLimit ?? 0) >>> 0) : 0;
  const headerMappedBytes = headerRvaLimit > rva ? headerRvaLimit - rva : reader.size - start;
  const end = Math.min(reader.size, start + headerMappedBytes);
  if (end <= start) return null;
  return {
    rvaStart: rva >>> 0,
    data: await reader.readBytes(start, end - start)
  };
};
