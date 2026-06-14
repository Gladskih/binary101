"use strict";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";
import { readResourceDirectory } from "./directory-reader.js";
import type { ResourceDirectoryReadResult } from "./directory-reader.js";
import { IMAGE_RESOURCE_DIRECTORY_SIZE } from "./directory-format.js";
import { validateResourceLayout } from "./layout-rules.js";
import { createResourceSpanResolver } from "./relative-offsets.js";
import type { ResourceTree } from "./tree-types.js";
import { createEmptyResourceTree } from "./tree-result.js";
import { buildResourcePathCollections } from "./tree-paths.js";
import type { ResourcePathCollections } from "./tree-path-collections.js";
import {
  createResourceLabelReader,
  createResourceLeafPathReader,
  createResourcePathNodeReader
} from "./tree-readers.js";
export type { ResourceLangEntry, ResourceDetailEntry, ResourceTree } from "./tree-types.js";

export const buildResourceTree = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<ResourceTree | null> => {
  const dir = dataDirs.find(d => d.name === "RESOURCE");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  return await buildPresentResourceTree(reader, dir, rvaToOff);
};

const buildPresentResourceTree = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  rvaToOff: RvaToOffset
): Promise<ResourceTree> => {
  if (dir.rva === 0) {
    return createEmptyResourceTree(
      dir,
      rvaToOff(dir.rva),
      ["Resource directory has a non-zero size but RVA is 0."]
    );
  }
  if (dir.size < IMAGE_RESOURCE_DIRECTORY_SIZE) {
    return createEmptyResourceTree(
      dir,
      rvaToOff(dir.rva),
      [
        "Resource directory is smaller than IMAGE_RESOURCE_DIRECTORY "
          + `(${IMAGE_RESOURCE_DIRECTORY_SIZE} bytes).`
      ]
    );
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return createEmptyResourceTree(
      dir,
      null,
      ["Resource directory RVA does not map to file data."]
    );
  }
  if (base < 0 || base >= reader.size) {
    return createEmptyResourceTree(
      dir,
      base,
      ["Resource directory starts outside file data."]
    );
  }
  return await parseResourceTree(reader, dir, base, base + dir.size, rvaToOff);
};

const parseResourceTree = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  base: number,
  limitEnd: number,
  rvaToOff: RvaToOffset
): Promise<ResourceTree> => {
  const resolver = createResourceSpanResolver(dir, base, reader.size, rvaToOff);
  const view: ResourceTree["view"] = async (offset, length) => reader.read(offset, length);
  const readLabel = createResourceLabelReader(reader, dir, resolver, new TextDecoder("utf-16le"));
  const readDirectory = (rel: number) =>
    readResourceDirectory(reader, dir, resolver, readLabel, rel);
  const readLeafPath = createResourceLeafPathReader(view, resolver);
  const readPathNode = createResourcePathNodeReader(readLabel);
  const root = await readDirectory(0);
  if (!root.directory) {
    return createRootlessResourceTree(dir, base, limitEnd, root.issues, view);
  }
  const paths = await buildResourcePathCollections(
    root.directory.entries,
    readDirectory,
    readLeafPath,
    readPathNode
  );
  const issues = collectResourceTreeIssues(root, paths, dir, base, reader.size);
  return {
    base,
    limitEnd,
    dirRva: dir.rva,
    dirSize: dir.size,
    ...(issues.length ? { issues } : {}),
    directories: [...(root.directoryInfo ? [root.directoryInfo] : []), ...paths.directories],
    top: paths.top,
    detail: paths.detail,
    ...(paths.paths.length ? { paths: paths.paths } : {}),
    view
  };
};

const createRootlessResourceTree = (
  dir: PeDataDirectory,
  base: number,
  limitEnd: number,
  issues: string[],
  view: ResourceTree["view"]
): ResourceTree => ({
  base,
  limitEnd,
  dirRva: dir.rva,
  dirSize: dir.size,
  ...(issues.length ? { issues } : {}),
  top: [],
  detail: [],
  paths: [],
  view
});

const collectResourceTreeIssues = (
  root: ResourceDirectoryReadResult,
  paths: ResourcePathCollections,
  dir: PeDataDirectory,
  base: number,
  fileSize: number
): string[] => [
  ...root.issues,
  ...paths.issues,
  ...validateResourceLayout(
    Math.max(root.maxDirectoryEnd, paths.maxDirectoryEnd),
    [...root.resourceStringRanges, ...paths.resourceStringRanges],
    paths.resourceDataEntries,
    [...root.resourceSubdirectoryTargets, ...paths.resourceSubdirectoryTargets],
    dir.rva,
    dir.size,
    base,
    fileSize
  )
];
