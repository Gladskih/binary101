import { detectEmbeddedResources } from "../embedded-resources/detect.js";
import type { ResourceReference, ResourceSymbol } from "../embedded-resources/types.js";
import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { isPeWindowsParseResult } from "./core/parse-result.js";
import { addResourceReferenceEvidence } from "../embedded-resources/references.js";
import type { CoffSymbol } from "../coff/debug-types.js";
import type { PeParseResult, PeWindowsParseResult } from "./core/parse-result.js";

const symbolEnds = (symbols: CoffSymbol[], rawSections: PeParseResult["sections"]): Map<string, number> => {
  const ends = new Map<string, number>();
  const sections = new Map<number, Set<number>>();
  for (const symbol of symbols) {
    const offsets = sections.get(symbol.sectionNumber) ?? new Set<number>();
    offsets.add(symbol.value);
    sections.set(symbol.sectionNumber, offsets);
  }
  for (const [sectionNumber, values] of sections) {
    const offsets = [...values].sort((left, right) => left - right);
    for (const [index, offset] of offsets.entries()) {
      ends.set(`${sectionNumber}:${offset}`, offsets[index + 1] ??
        rawSections[sectionNumber - 1]?.sizeOfRawData ?? 0);
    }
  }
  return ends;
};

const resourceSymbols = (pe: PeParseResult): ResourceSymbol[] => {
  const symbols = pe.coffDebug?.symbols ?? [];
  if (!symbols.some(symbol => symbol.name.includes("qt_resource_"))) return [];
  const result: ResourceSymbol[] = [];
  const ends = symbolEnds(symbols, pe.sections);
  let scope = "COFF symbol table";
  for (const symbol of symbols) {
    if (symbol.storageClass === 103) scope = `COFF file symbol #${symbol.index}`;
    const section = pe.sections[symbol.sectionNumber - 1];
    if (!symbol.name.includes("qt_resource_") || !section || symbol.value >= section.sizeOfRawData) continue;
    result.push({ name: symbol.name, scope, offset: section.pointerToRawData + symbol.value,
      size: Math.min(ends.get(`${symbol.sectionNumber}:${symbol.value}`)!, section.sizeOfRawData) - symbol.value });
  }
  return result;
};

const readRelocatedAddress = async (reader: FileRangeReader, site: number, type: number): Promise<bigint | null> => {
  const width = type === 10 ? 8 : 4;
  const view = await reader.read(site, width);
  if (view.byteLength !== width) return null;
  return type === 10 ? view.getBigUint64(0, true) : BigInt(view.getUint32(0, true));
};

const relocationReference = async (reader: FileRangeReader, pe: PeWindowsParseResult,
  siteRva: number, type: number): Promise<ResourceReference | null> => {
  const site = pe.rvaToOff(siteRva);
  if (site === null) return null;
  const address = await readRelocatedAddress(reader, site, type);
  if (address === null) return null;
  const rva = address - pe.opt.ImageBase;
  if (rva < 0n || rva > 0xffffffffn) return null;
  const targetOffset = pe.rvaToOff(Number(rva));
  return targetOffset === null ? null : { targetOffset,
    description: `PE base relocation at ${site} points to resource bytes` };
};

const relocationReferences = async (file: File, pe: PeParseResult): Promise<ResourceReference[]> => {
  if (!isPeWindowsParseResult(pe) || !pe.reloc) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const references: ResourceReference[] = [];
  for (const block of pe.reloc.blocks) {
    for (const entry of block.entries) {
      // Microsoft PE/COFF Base Relocation Types: HIGHLOW (3), DIR64 (10).
      if (entry.type !== 3 && entry.type !== 10) continue;
      const reference = await relocationReference(reader, pe, block.pageRva + entry.offset, entry.type);
      if (reference) references.push(reference);
    }
  }
  return references;
};

export const analyzePeEmbeddedResources = async (file: File, pe: PeParseResult) => {
  const result = await detectEmbeddedResources(file, pe.sections.map(section => ({ name: section.name.value,
    offset: section.pointerToRawData, size: section.sizeOfRawData })), resourceSymbols(pe));
  if (result?.bundles.length) addResourceReferenceEvidence(result, await relocationReferences(file, pe));
  return result;
};
