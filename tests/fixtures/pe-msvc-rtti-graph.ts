"use strict";

export interface MsvcRttiFixtureType {
  rva: number;
  nameRva: number;
  decoratedName: string;
}

export interface MsvcRttiFixturePmd {
  mdisp: number;
  pdisp: number;
  vdisp: number;
}

export interface MsvcRttiFixtureHierarchyNode {
  type: MsvcRttiFixtureType;
  hierarchyRva: number;
  pmd: MsvcRttiFixturePmd;
  attributes: number;
  children: MsvcRttiFixtureHierarchyNode[];
}

export interface MsvcRttiFixtureHierarchy {
  rva: number;
  baseClassArrayRva: number;
  baseDescriptorRvas: number[];
  type: MsvcRttiFixtureType;
  root: MsvcRttiFixtureHierarchyNode;
}

export interface MsvcRttiFixtureBase {
  hierarchy: MsvcRttiFixtureHierarchy;
  pmd?: MsvcRttiFixturePmd;
  attributes?: number;
}

export const copyMsvcRttiFixtureHierarchy = (
  hierarchy: MsvcRttiFixtureHierarchy,
  pmd: MsvcRttiFixturePmd,
  attributes: number,
  hasHierarchyAttribute: number
): MsvcRttiFixtureHierarchyNode => ({
  type: hierarchy.type,
  hierarchyRva: hierarchy.rva,
  pmd,
  attributes: attributes | hasHierarchyAttribute,
  children: hierarchy.root.children.map(child => copyMsvcRttiFixtureNode(child))
});

const copyMsvcRttiFixtureNode = (
  node: MsvcRttiFixtureHierarchyNode
): MsvcRttiFixtureHierarchyNode => ({
  ...node,
  pmd: { ...node.pmd },
  children: node.children.map(child => copyMsvcRttiFixtureNode(child))
});

export const flattenMsvcRttiFixtureNodes = (
  root: MsvcRttiFixtureHierarchyNode
): MsvcRttiFixtureHierarchyNode[] =>
  [root, ...root.children.flatMap(child => flattenMsvcRttiFixtureNodes(child))];

export const msvcRttiFixtureDescendantCount = (
  node: MsvcRttiFixtureHierarchyNode
): number => node.children.reduce(
  (count, child) => count + 1 + msvcRttiFixtureDescendantCount(child),
  0
);

