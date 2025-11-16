"use strict";

import { buildResourceTree } from "./pe-resources-core.js";
import { enrichResourcePreviews } from "./pe-resources-preview.js";

export async function parseResources(file, dataDirs, rvaToOff, addCoverageRegion) {
  const tree = await buildResourceTree(file, dataDirs, rvaToOff, addCoverageRegion);
  if (!tree) return null;
  return enrichResourcePreviews(file, tree);
}

// Backwards-compatible alias used earlier in refactor.
export const parseResourcesSummary = parseResources;
