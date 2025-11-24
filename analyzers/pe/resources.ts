// @ts-nocheck
"use strict";

import { buildResourceTree } from "./resources-core.js";
import { enrichResourcePreviews } from "./resources-preview.js";

export async function parseResources(file, dataDirs, rvaToOff, addCoverageRegion) {
  const tree = await buildResourceTree(file, dataDirs, rvaToOff, addCoverageRegion);
  if (!tree) return null;
  return enrichResourcePreviews(file, tree);
}
