"use strict";

import { buildResourceTree } from "./resources-core.js";
import { enrichResourcePreviews } from "./resources-preview.js";
import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

export async function parseResources(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<unknown> {
  const tree = await buildResourceTree(file, dataDirs, rvaToOff, addCoverageRegion);
  if (!tree) return null;
  return enrichResourcePreviews(file, tree);
}
