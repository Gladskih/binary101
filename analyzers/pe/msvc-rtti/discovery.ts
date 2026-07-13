"use strict";

import type { MsvcRttiGraphParser } from "./graph-parser.js";
import type { MsvcRttiImage } from "./image.js";
import {
  COMPLETE_OBJECT_LOCATOR_SIZE,
  IMAGE_POINTER_SIZE,
  MSVC_RTTI_LAYOUT
} from "./layout.js";
import type {
  MsvcRttiAnalysis,
  MsvcRttiBaseClass,
  MsvcRttiClassHierarchy,
  MsvcRttiCompleteObjectLocator,
  MsvcRttiTypeDescriptor,
  MsvcRttiVftable
} from "./types.js";
import { parseRelocationBackedVftable } from "./vftable.js";

interface AcceptedRtti {
  completeObjectLocator: MsvcRttiCompleteObjectLocator;
  vftable: MsvcRttiVftable;
}

interface DiscoveryCandidate {
  locatorRva: number;
  firstFunctionTargetRva: number;
}

const readDiscoveryCandidate = async (
  image: MsvcRttiImage,
  dir64Sites: Set<number>,
  locatorSlotRva: number
): Promise<DiscoveryCandidate | null> => {
  const firstFunctionSlotRva = locatorSlotRva + IMAGE_POINTER_SIZE;
  if (!Number.isSafeInteger(firstFunctionSlotRva) ||
    !dir64Sites.has(firstFunctionSlotRva) ||
    !image.isDataRange(firstFunctionSlotRva, IMAGE_POINTER_SIZE, IMAGE_POINTER_SIZE)) return null;
  // Keep these adjacent reads sequential so FileRangeReader's shared window can serve both.
  const locatorRva = await image.readPreferredVaRva(locatorSlotRva);
  if (locatorRva == null ||
    !image.isDataRange(locatorRva, COMPLETE_OBJECT_LOCATOR_SIZE, 4)) return null;
  const firstFunctionTargetRva = await image.readPreferredVaRva(firstFunctionSlotRva);
  return firstFunctionTargetRva != null && image.isExecutableRva(firstFunctionTargetRva)
    ? { locatorRva, firstFunctionTargetRva }
    : null;
};

const collectBaseClassGraph = (
  graph: MsvcRttiGraphParser,
  node: MsvcRttiBaseClass,
  types: Map<number, MsvcRttiTypeDescriptor>,
  hierarchies: Map<number, MsvcRttiClassHierarchy>
): void => {
  const type = graph.getTypeDescriptor(node.typeDescriptorRva);
  if (type) types.set(type.rva, type);
  collectHierarchyGraph(graph, node.classHierarchyDescriptorRva, types, hierarchies);
  node.children.forEach(child => collectBaseClassGraph(graph, child, types, hierarchies));
};

const collectHierarchyGraph = (
  graph: MsvcRttiGraphParser,
  rva: number,
  types: Map<number, MsvcRttiTypeDescriptor>,
  hierarchies: Map<number, MsvcRttiClassHierarchy>
): void => {
  if (hierarchies.has(rva)) return;
  const hierarchy = graph.getClassHierarchy(rva);
  if (!hierarchy) return;
  hierarchies.set(rva, hierarchy);
  collectBaseClassGraph(graph, hierarchy.root, types, hierarchies);
};

const buildResult = (
  accepted: AcceptedRtti[],
  graph: MsvcRttiGraphParser
): MsvcRttiAnalysis => {
  const types = new Map<number, MsvcRttiTypeDescriptor>();
  const hierarchies = new Map<number, MsvcRttiClassHierarchy>();
  const completeObjectLocators = new Map<number, MsvcRttiCompleteObjectLocator>();
  const vftables = new Map<number, MsvcRttiVftable>();
  for (const item of accepted) {
    completeObjectLocators.set(item.completeObjectLocator.rva, item.completeObjectLocator);
    vftables.set(item.vftable.rva, item.vftable);
    const type = graph.getTypeDescriptor(item.completeObjectLocator.typeDescriptorRva);
    if (type) types.set(type.rva, type);
    collectHierarchyGraph(
      graph,
      item.completeObjectLocator.classHierarchyDescriptorRva,
      types,
      hierarchies
    );
  }
  const byRva = <Type extends { rva: number }>(values: Iterable<Type>): Type[] =>
    [...values].sort((left, right) => left.rva - right.rva);
  return {
    layout: MSVC_RTTI_LAYOUT,
    types: byRva(types.values()),
    classHierarchies: byRva(hierarchies.values()),
    completeObjectLocators: byRva(completeObjectLocators.values()),
    vftables: byRva(vftables.values())
  };
};

export const discoverMsvcRtti = async (
  image: MsvcRttiImage,
  dir64Sites: Set<number>,
  graph: MsvcRttiGraphParser
): Promise<MsvcRttiAnalysis | null> => {
  const accepted: AcceptedRtti[] = [];
  for (const locatorSlotRva of dir64Sites) {
    const candidate = await readDiscoveryCandidate(image, dir64Sites, locatorSlotRva);
    if (!candidate) continue;
    const completeObjectLocator = await graph.completeObjectLocator(candidate.locatorRva);
    if (!completeObjectLocator) continue;
    const vftable = await parseRelocationBackedVftable(
      image,
      dir64Sites,
      locatorSlotRva,
      completeObjectLocator.rva,
      candidate.firstFunctionTargetRva
    );
    if (vftable) accepted.push({ completeObjectLocator, vftable });
  }
  return accepted.length ? buildResult(accepted, graph) : null;
};
