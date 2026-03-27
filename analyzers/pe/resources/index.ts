"use strict";

import { buildResourceTree } from "./core.js";
import { enrichResourcePreviews } from "./preview/index.js";
import type { ResourceDetailGroup } from "./preview/types.js";
import type { ResourceTree } from "./tree-types.js";
import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "../types.js";

export interface PeResources {
  top: ResourceTree["top"];
  detail: ResourceDetailGroup[];
  directories?: ResourceTree["directories"];
  issues?: string[];
}

export async function parseResources(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<PeResources | null> {
  const tree = await buildResourceTree(file, dataDirs, rvaToOff, addCoverageRegion);
  if (!tree) return null;
  return enrichResourcePreviews(file, tree);
}
