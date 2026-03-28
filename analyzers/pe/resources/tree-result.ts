"use strict";

import type { PeDataDirectory, RvaToOffset } from "../types.js";
import type { ResourceDirectoryInfo, ResourceTree } from "./tree-types.js";

export const createEmptyResourceTree = (
  dir: PeDataDirectory,
  base: number | null,
  issues: string[],
  rvaToOff: RvaToOffset
): ResourceTree => ({
  base: base ?? 0,
  limitEnd: (base ?? 0) + (dir.size >>> 0),
  dirRva: dir.rva,
  dirSize: dir.size,
  ...(issues.length ? { issues } : {}),
  top: [],
  detail: [],
  paths: [],
  view: async () => new DataView(new ArrayBuffer(0)),
  rvaToOff
});

export const createResourceTreeResult = (
  dir: PeDataDirectory,
  base: number,
  limitEnd: number,
  issues: string[],
  directories: ResourceDirectoryInfo[],
  top: ResourceTree["top"],
  detail: ResourceTree["detail"],
  paths: ResourceTree["paths"],
  view: ResourceTree["view"],
  rvaToOff: RvaToOffset
): ResourceTree => ({
  base,
  limitEnd,
  dirRva: dir.rva,
  dirSize: dir.size,
  ...(issues.length ? { issues } : {}),
  ...(directories.length ? { directories } : {}),
  top,
  detail,
  ...(paths?.length ? { paths } : {}),
  view,
  rvaToOff
});
