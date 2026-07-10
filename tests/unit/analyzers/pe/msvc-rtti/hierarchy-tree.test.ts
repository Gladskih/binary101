"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { buildMsvcRttiHierarchyTree } from "../../../../../analyzers/pe/msvc-rtti/hierarchy-tree.js";
import type { MsvcRttiBaseClass } from "../../../../../analyzers/pe/msvc-rtti/types.js";

const baseClass = (
  descriptorRva: number,
  numContainedBases: number
): MsvcRttiBaseClass => ({
  descriptorRva,
  typeDescriptorRva: descriptorRva + 0x1000,
  numContainedBases,
  pmd: { mdisp: 0, pdisp: -1, vdisp: 0 },
  attributes: 0x40,
  classHierarchyDescriptorRva: descriptorRva + 0x2000,
  children: []
});

void test("buildMsvcRttiHierarchyTree reconstructs preorder subtree spans", () => {
  const entries = [
    baseClass(0x100, 4),
    baseClass(0x200, 2),
    baseClass(0x300, 0),
    baseClass(0x400, 0),
    baseClass(0x500, 0)
  ];

  const root = buildMsvcRttiHierarchyTree(entries);

  assert.ok(root);
  assert.deepEqual(
    root.children.map(child => ({
      descriptorRva: child.descriptorRva,
      children: child.children.map(grandchild => grandchild.descriptorRva)
    })),
    [
      { descriptorRva: 0x200, children: [0x300, 0x400] },
      { descriptorRva: 0x500, children: [] }
    ]
  );
  assert.equal(entries[0]?.children.length, 0);
});

void test("buildMsvcRttiHierarchyTree rejects an empty array", () => {
  assert.equal(buildMsvcRttiHierarchyTree([]), null);
});

void test("buildMsvcRttiHierarchyTree requires root coverage of the complete array", () => {
  assert.equal(buildMsvcRttiHierarchyTree([baseClass(0x100, 0), baseClass(0x200, 0)]), null);
});

void test("buildMsvcRttiHierarchyTree rejects a child subtree beyond its parent", () => {
  const entries = [
    baseClass(0x100, 3),
    baseClass(0x200, 1),
    baseClass(0x300, 1),
    baseClass(0x400, 0)
  ];

  const root = buildMsvcRttiHierarchyTree(entries);

  assert.equal(root, null);
});

void test("buildMsvcRttiHierarchyTree keeps repeated descriptor addresses as distinct nodes", () => {
  const entries = [baseClass(0x100, 2), baseClass(0x200, 0), baseClass(0x200, 0)];

  const root = buildMsvcRttiHierarchyTree(entries);

  assert.ok(root);
  assert.equal(root.children.length, 2);
  assert.equal(root.children[0]?.descriptorRva, root.children[1]?.descriptorRva);
  assert.notEqual(root.children[0], root.children[1]);
});

