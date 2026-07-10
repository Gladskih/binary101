"use strict";

import type { MsvcRttiBaseClass } from "./types.js";

interface PendingNode {
  endIndex: number;
  node: MsvcRttiBaseClass;
}

const cloneNode = (node: MsvcRttiBaseClass): MsvcRttiBaseClass => ({ ...node, children: [] });

export const buildMsvcRttiHierarchyTree = (
  entries: MsvcRttiBaseClass[]
): MsvcRttiBaseClass | null => {
  const first = entries[0];
  if (!first || first.numContainedBases !== entries.length - 1) return null;
  const root = cloneNode(first);
  const pending: PendingNode[] = [{ node: root, endIndex: entries.length - 1 }];
  for (let index = 1; index < entries.length; index += 1) {
    while (pending.length && index > pending[pending.length - 1]!.endIndex) pending.pop();
    const parent = pending[pending.length - 1];
    const source = entries[index];
    if (!parent || !source) return null;
    const endIndex = index + source.numContainedBases;
    if (endIndex >= entries.length || endIndex > parent.endIndex) return null;
    const node = cloneNode(source);
    parent.node.children.push(node);
    if (source.numContainedBases) pending.push({ node, endIndex });
  }
  return root;
};

