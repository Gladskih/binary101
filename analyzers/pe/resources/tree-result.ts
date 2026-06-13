"use strict";

import type { PeDataDirectory } from "../types.js";
import type { ResourceTree } from "./tree-types.js";

export const createEmptyResourceTree = (
  dir: PeDataDirectory,
  base: number | null,
  issues: string[]
): ResourceTree => ({
  base: base ?? 0,
  limitEnd: (base ?? 0) + (dir.size >>> 0),
  dirRva: dir.rva,
  dirSize: dir.size,
  ...(issues.length ? { issues } : {}),
  top: [],
  detail: [],
  paths: [],
  view: async () => new DataView(new ArrayBuffer(0))
});
