import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { decodeGResource } from "./gresource.js";
import { decodeRcc, decodeRccArrays } from "./rcc.js";
import { findResourceSignatures } from "./signatures.js";
import { findRccArraySymbols } from "./rcc-symbols.js";
import { previewEmbeddedResources } from "./content.js";
import { addResourceReferenceEvidence } from "./references.js";
import type { EmbeddedResourceAnalysis, ResourceReference, ResourceSection, ResourceSymbol } from "./types.js";

const detectContainers = async (file: File, reader: FileRangeReader, sections: ResourceSection[],
  analysis: EmbeddedResourceAnalysis): Promise<void> => {
  for await (const candidate of findResourceSignatures(file, sections)) {
    const result = await (candidate.kind === "rcc" ? decodeRcc : decodeGResource)(
      reader, candidate.offset, candidate.end - candidate.offset);
    // Signature literals also occur in executable code. Only validated objects are resources.
    if (!result.value) {
      const named = sections.find(section => section.offset === candidate.offset &&
        section.name.startsWith(".gresource."));
      if (named) analysis.issues.push(`${named.name}: ${result.issues.join("; ")}`);
      continue;
    }
    analysis.bundles.push({ offset: candidate.offset, evidence: [
      candidate.kind === "rcc" ? "qres signature and validated RCC tables" :
        "GVDB signature, hash table, hierarchy and (uuay) values"
    ], resource: result.value, issues: result.issues });
  }
};

const detectArrays = async (reader: FileRangeReader, symbols: ResourceSymbol[],
  analysis: EmbeddedResourceAnalysis): Promise<void> => {
  const trees = new Set(analysis.bundles.flatMap(bundle =>
    bundle.resource.format === "Qt RCC" ? [bundle.resource.tree.offset] : []));
  for (const arrays of findRccArraySymbols(symbols)) {
    if (trees.has(arrays.tree.offset)) continue;
    const result = await decodeRccArrays(reader, arrays.tree, arrays.names, arrays.data);
    if (!result.value) {
      analysis.issues.push(`Qt array symbols at ${arrays.tree.offset}: ${result.issues.join("; ")}`);
      continue;
    }
    trees.add(arrays.tree.offset);
    analysis.bundles.push({ offset: arrays.tree.offset, evidence: [
      `RCC array symbols in ${arrays.tree.scope}`, "Validated RCC tables and unique node layout"
    ], resource: result.value, issues: result.issues });
  }
};

export const detectEmbeddedResources = async (file: File, sections: ResourceSection[],
  symbols: ResourceSymbol[], references: ResourceReference[] = []): Promise<EmbeddedResourceAnalysis | null> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const analysis: EmbeddedResourceAnalysis = { bundles: [], issues: [] };
  await detectContainers(file, reader, sections, analysis);
  await detectArrays(reader, symbols, analysis);
  // Automatic preview is bounded; metadata and payload ranges remain available for every entry.
  const budget = { remainingBytes: 16 * 1024 * 1024 };
  addResourceReferenceEvidence(analysis, references);
  for (const bundle of analysis.bundles) {
    bundle.issues.push(...await previewEmbeddedResources(reader, bundle.resource, budget));
  }
  return analysis.bundles.length || analysis.issues.length ? analysis : null;
};
