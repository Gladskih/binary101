"use strict";

import type { ResourceDirectoryReadResult } from "./directory-reader.js";
import type { ResourceDirectoryEntry } from "./directory-rules.js";
import {
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE
} from "./directory-format.js";
import { formatResourceRelOffset } from "./relative-offsets.js";
import type { ResourcePathNode } from "./tree-types.js";
import type {
  ResourceLeafPathReadResult,
  ResourcePathNodeReadResult
} from "./tree-readers.js";
import {
  appendResourcePathIssue,
  createEmptyResourcePathCollections,
  mergeDirectoryReadResult,
  mergeLeafReadResult,
  mergePathNodeReadResult,
  type ResourcePathCollections
} from "./tree-path-collections.js";

type ResourceDirectoryTraversalFrame = {
  entries?: ResourceDirectoryEntry[];
  index: number;
  localDirectoryEnd?: number;
  nodes: ResourcePathNode[];
  rel: number;
};

export type ReadResourceDirectory = (rel: number) => Promise<ResourceDirectoryReadResult>;
export type ReadResourceLeafPath = (
  target: number,
  nodes: ResourcePathNode[]
) => Promise<ResourceLeafPathReadResult>;
export type ReadResourcePathNode = (
  entry: ResourceDirectoryEntry
) => Promise<ResourcePathNodeReadResult>;

const readDirectoryForFrame = async (
  frame: ResourceDirectoryTraversalFrame,
  readDirectory: ReadResourceDirectory,
  collections: ResourcePathCollections,
  expandedDirectories: Set<number>
): Promise<{
  collections: ResourcePathCollections;
  entries: ResourceDirectoryEntry[] | null;
}> => {
  if (expandedDirectories.has(frame.rel)) {
    return {
      collections: appendResourcePathIssue(
        collections,
        `Resource directory graph re-enters ${formatResourceRelOffset(frame.rel)} from multiple `
          + "parent paths; skipping repeated traversal."
      ),
      entries: null
    };
  }
  expandedDirectories.add(frame.rel);
  const directory = await readDirectory(frame.rel);
  const nextCollections = mergeDirectoryReadResult(collections, directory);
  if (!directory.directory) return { collections: nextCollections, entries: null };
  frame.entries = directory.directory.entries;
  frame.localDirectoryEnd = frame.rel + IMAGE_RESOURCE_DIRECTORY_SIZE
    + directory.directory.entries.length * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  return { collections: nextCollections, entries: frame.entries };
};

const readLeafEntry = async (
  entry: ResourceDirectoryEntry,
  nodes: ResourcePathNode[],
  typeName: string,
  frameDepth: number,
  readLeafPath: ReadResourceLeafPath,
  collections: ResourcePathCollections
): Promise<ResourcePathCollections> => {
  const leafResult = await readLeafPath(entry.target, nodes);
  const nextCollections = mergeLeafReadResult(collections, leafResult);
  if (!leafResult.leaf) return nextCollections;
  if (frameDepth === 1) {
    return appendResourcePathIssue(
      nextCollections,
      `Resource entry under type ${typeName} points directly to data; `
        + "second-level entries should point to language subdirectories."
    );
  }
  return nextCollections;
};

const readNextFrameEntry = (
  frame: ResourceDirectoryTraversalFrame
): ResourceDirectoryEntry | null => {
  const entry = frame.entries?.[frame.index];
  if (!entry) return null;
  frame.index += 1;
  return entry;
};

const pushSubdirectoryFrame = (
  frames: ResourceDirectoryTraversalFrame[],
  nextNodes: ResourcePathNode[],
  target: number
): void => {
  frames.push({
    index: 0,
    nodes: nextNodes,
    rel: target
  });
};

const handleFrameEntry = async (
  frame: ResourceDirectoryTraversalFrame,
  entry: ResourceDirectoryEntry,
  typeName: string,
  frames: ResourceDirectoryTraversalFrame[],
  readLeafPath: ReadResourceLeafPath,
  readPathNode: ReadResourcePathNode,
  collections: ResourcePathCollections
): Promise<ResourcePathCollections> => {
  const node = await readPathNode(entry);
  const nextCollections = mergePathNodeReadResult(collections, node);
  const nextNodes = [...frame.nodes, node.node];
  const localDirectoryEnd = frame.localDirectoryEnd!;
  if (entry.target < localDirectoryEnd) {
    return appendResourcePathIssue(
      nextCollections,
      `Resource ${entry.subdir ? "subdirectory" : "data entry"} at `
        + `${formatResourceRelOffset(entry.target)} points into the current directory-entry area `
        + `at ${formatResourceRelOffset(frame.rel)}.`
    );
  }
  if (entry.subdir) {
    pushSubdirectoryFrame(frames, nextNodes, entry.target);
    return nextCollections;
  }
  return await readLeafEntry(
    entry,
    nextNodes,
    typeName,
    frame.nodes.length,
    readLeafPath,
    nextCollections
  );
};

const advanceTraversal = async (
  frames: ResourceDirectoryTraversalFrame[],
  typeName: string,
  readDirectory: ReadResourceDirectory,
  readLeafPath: ReadResourceLeafPath,
  readPathNode: ReadResourcePathNode,
  collections: ResourcePathCollections,
  expandedDirectories: Set<number>
): Promise<ResourcePathCollections> => {
  const frame = frames[frames.length - 1]!;
  let nextCollections = collections;
  if (!frame.entries) {
    const directoryFrame = await readDirectoryForFrame(
      frame,
      readDirectory,
      collections,
      expandedDirectories
    );
    nextCollections = directoryFrame.collections;
  }
  const entry = readNextFrameEntry(frame);
  if (!entry) {
    frames.pop();
    return nextCollections;
  }
  return await handleFrameEntry(
    frame,
    entry,
    typeName,
    frames,
    readLeafPath,
    readPathNode,
    nextCollections
  );
};

export const collectResourceLeafPaths = async (
  typeName: string,
  rel: number,
  nodes: ResourcePathNode[],
  readDirectory: ReadResourceDirectory,
  readLeafPath: ReadResourceLeafPath,
  readPathNode: ReadResourcePathNode,
  expandedDirectories: Set<number>
): Promise<ResourcePathCollections> => {
  let collections = createEmptyResourcePathCollections();
  const frames: ResourceDirectoryTraversalFrame[] = [{
    index: 0,
    nodes,
    rel
  }];
  while (frames.length) {
    collections = await advanceTraversal(
      frames,
      typeName,
      readDirectory,
      readLeafPath,
      readPathNode,
      collections,
      expandedDirectories
    );
  }
  return collections;
};
