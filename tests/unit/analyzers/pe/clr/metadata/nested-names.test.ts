"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveDefinitionNames, resolveReferenceNames, resolveExportedTypeNames }
  from "../../../../../../analyzers/pe/clr/metadata-nested-names.js";
import type { PeClrTypeDefinitionInfo, PeClrTypeReferenceInfo }
  from "../../../../../../analyzers/pe/clr/types.js";

const index = (tableId: number, row: number) => ({ table: "fixture", tableId, row, raw: row, valid: true });
const definition = (row: number, name: string | null): PeClrTypeDefinitionInfo => ({
  row, name, namespace: "Demo", fullName: name ? `Demo.${name}` : null,
  flags: 0, extends: index(1, 1), fieldStart: 1, fieldEnd: null, methodStart: 1, methodEnd: null
});
const reference = (row: number, parent: number): PeClrTypeReferenceInfo => ({
  row, name: `T${row}`, namespace: "Demo", fullName: `Demo.T${row}`, resolutionScope: index(1, parent)
});

void test("resolves nested exported types through their Implementation chain", () => {
  assert.deepEqual(resolveExportedTypeNames([
    { row: 1, name: "Child", namespace: "", fullName: "Child", flags: 0, typeDefId: 0, implementation: index(39, 2) },
    { row: 2, name: "Parent", namespace: "Demo", fullName: "Demo.Parent", flags: 0, typeDefId: 0,
      implementation: index(35, 1) }
  ], []).map(type => type.fullName), ["Demo.Parent+Child", "Demo.Parent"]);
  assert.equal(resolveExportedTypeNames([
    { row: 1, name: "Child", namespace: "", fullName: "Child", flags: 0, typeDefId: 0,
      implementation: { ...index(39, 1), valid: false } }
  ], [])[0]!.fullName, null);
});

void test("preserves the distinction between literal plus signs and nested-name separators", () => {
  const types = [definition(1, "Outer"), definition(2, "Child+Literal")];
  assert.equal(resolveDefinitionNames(types,
    [{ NestedClass: index(2, 2), EnclosingClass: index(2, 1) }], [])[1]!.fullName, "Demo.Outer+Child\\+Literal");
});

void test("resolves nesting declared out of order and preserves top-level names", () => {
  const issues: string[] = [];
  const types = [definition(1, "Outer"), definition(2, "Inner"), definition(3, "Leaf")];
  const result = resolveDefinitionNames(types, [
    { NestedClass: index(2, 3), EnclosingClass: index(2, 2) },
    { NestedClass: index(2, 2), EnclosingClass: index(2, 1) }
  ], issues);
  assert.deepEqual(result.map(type => type.fullName), ["Demo.Outer", "Demo.Outer+Inner", "Demo.Outer+Inner+Leaf"]);
  assert.equal(types[1]?.fullName, "Demo.Inner");
  assert.deepEqual(issues, []);
});

void test("resolves TypeRef nesting and warns on cycles and invalid scopes", () => {
  const issues: string[] = [];
  assert.deepEqual(resolveReferenceNames([
    { ...reference(1, 0), resolutionScope: index(35, 1) }, reference(2, 1)
  ], issues).map(type => type.fullName), ["Demo.T1", "Demo.T1+T2"]);
  assert.deepEqual(resolveReferenceNames([reference(1, 2), reference(2, 1)], issues)
    .map(type => type.fullName), [null, null]);
  assert.equal(resolveReferenceNames([{ ...reference(1, 2), resolutionScope: { ...index(1, 2), valid: false } }],
    issues)[0]?.fullName, null);
  assert.equal(resolveReferenceNames([reference(1, 2)], issues)[0]?.fullName, null);
  assert.ok(issues.length >= 3);
});

void test("rejects missing, out-of-range and duplicate enclosing definitions", () => {
  const issues: string[] = [];
  const result = resolveDefinitionNames([definition(1, "Outer"), definition(2, "Inner")], [
    {}, { NestedClass: 1 }, { NestedClass: index(1, 1) }, { NestedClass: index(2, 0) },
    { NestedClass: index(2, 3) }, { NestedClass: index(2, 1), EnclosingClass: index(2, 3) },
    { NestedClass: index(2, 2), EnclosingClass: index(2, 1) },
    { NestedClass: index(2, 2), EnclosingClass: index(2, 1) }
  ], issues);
  assert.deepEqual(result.map(type => type.fullName), [null, null]);
  assert.equal(issues.length, 8);
});

void test("preserves unknown names and handles deep chains without recursive calls", () => {
  const types = Array.from({ length: 2000 }, (_, row) => definition(row + 1, "T"));
  assert.equal(resolveDefinitionNames(types, types.slice(1).map(type => ({
    NestedClass: index(2, type.row), EnclosingClass: index(2, type.row - 1)
  })), [])[1999]?.fullName, `Demo.T${"+T".repeat(1999)}`);
  assert.equal(resolveDefinitionNames([definition(1, null)], [], [])[0]?.fullName, null);
  assert.equal(resolveDefinitionNames([definition(1, "T"), definition(2, null)], [
    { NestedClass: index(2, 2), EnclosingClass: index(2, 1) }
  ], [])[1]?.fullName, null);
  assert.deepEqual(resolveDefinitionNames([], [], []), []);
});

void test("unwinds names when parent rows follow the nested type", () => {
  assert.deepEqual(resolveDefinitionNames([definition(1, "Leaf"), definition(2, "Outer"), definition(3, "Inner")], [
    { NestedClass: index(2, 1), EnclosingClass: index(2, 3) },
    { NestedClass: index(2, 3), EnclosingClass: index(2, 2) }
  ], []).map(type => type.fullName), ["Demo.Outer+Inner+Leaf", "Demo.Outer", "Demo.Outer+Inner"]);
});

for (const enclosing of [undefined, 1, index(1, 1), index(2, 0), index(2, -1),
  { ...index(2, 1), valid: false }]) {
  void test(`rejects enclosing reference ${JSON.stringify(enclosing)}`, () => {
    const issues: string[] = [];
    assert.equal(resolveDefinitionNames([definition(1, "T")], [{ NestedClass: index(2, 1),
      ...(enclosing === undefined ? {} : { EnclosingClass: enclosing }) }], issues)[0]?.fullName, null);
    assert.match(issues[0]!, /invalid or duplicate enclosing type/);
  });
}
