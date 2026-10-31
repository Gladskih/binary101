import type { EmbeddedResourceAnalysis, ResourceReference } from "./types.js";

// Relocations supplement structural confirmation; a reference never creates a resource by itself.
export const addResourceReferenceEvidence = (analysis: EmbeddedResourceAnalysis,
  references: ResourceReference[]): void => {
  const targets = new Map<number, Set<string>>();
  for (const reference of references) {
    const evidence = targets.get(reference.targetOffset) ?? new Set<string>();
    evidence.add(reference.description);
    targets.set(reference.targetOffset, evidence);
  }
  for (const bundle of analysis.bundles) {
    const offsets = bundle.resource.format === "Qt RCC" ? [bundle.offset, bundle.resource.tree.offset,
      bundle.resource.names.offset, bundle.resource.data.offset] : [bundle.offset];
    bundle.evidence.push(...new Set(offsets.flatMap(offset => [...targets.get(offset) ?? []])));
  }
};
