import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeCodeViewScopeChains, codeViewScopeEndType, codeViewScopeLength, codeViewScopeLinks,
  codeViewScopeLocation, isCodeViewCallable } from "../../../../../analyzers/pe/debug/codeview-scope-links.js";
import type { LegacyCodeViewSymbol } from "../../../../../analyzers/pe/debug/legacy-codeview-symbol-records.js";

const procedure = (next: number, segment = 1): LegacyCodeViewSymbol => ({ type: 0x1110, procedure: {
  referenceKind: "typeIndex", scopeOffsets: { parent: 0, end: 64, next }, codeLength: 16,
  storedLocation: { segment, offset: 0 } } });
const thunk = (next: number): LegacyCodeViewSymbol => ({ type: 0x1102, scope: { kind: "thunk",
  scopeOffsets: { parent: 0, end: 128, next }, codeLength: 8, location: { segment: 1, offset: 16 } } });

void test("Procedure and thunk next chains may run backward in the physical stream", () => {
  const index = new Map([[4, procedure(0)], [80, thunk(4)]]);

  assert.equal(analyzeCodeViewScopeChains(index).size, 0);
  assert.equal(isCodeViewCallable(index.get(80)!), true);
  assert.equal(codeViewScopeLength(index.get(80)!), 8);
  assert.equal(codeViewScopeLocation(index.get(80)!)?.offset, 16);
  assert.equal(codeViewScopeLinks(index.get(80)!)?.parent, 0);
});

void test("Cycle validation includes the preceding tail and independent later components", () => {
  const index = new Map([[4, procedure(80)], [80, thunk(160)], [160, procedure(80)], [240, procedure(0)],
    [320, procedure(160)]]);
  const issues = analyzeCodeViewScopeChains(index);

  assert.equal(issues.size, 4);
  assert.ok([...issues.values()].every(issue => issue.includes("cycle")));
  assert.equal(issues.has(index.get(240)!), false);
});

void test("Distinct acyclic chains may join a previously validated tail", () => {
  const index = new Map([[4, procedure(80)], [80, thunk(0)], [160, procedure(80)]]);

  assert.equal(analyzeCodeViewScopeChains(index).size, 0);
});

void test("Scope next links reject absent, self, non-callable, nested and cross-segment targets", () => {
  const index = new Map([[4, procedure(999)], [80, procedure(80)], [160, procedure(240)], [240, { type: 6 }],
    [320, procedure(400)], [400, procedure(0, 2)], [480, procedure(560)], [560, procedure(0)]]);
  index.get(560)!.procedure!.scopeOffsets!.parent = 4;
  const issues = analyzeCodeViewScopeChains(index);

  assert.equal(issues.size, 5);
  assert.match(issues.get(index.get(4)!)!, /next link/);
  assert.match(issues.get(index.get(320)!)!, /crosses segments/);
  assert.match(issues.get(index.get(480)!)!, /non-outermost/);
});

void test("Unavailable target segment fields remain explicit rather than validated", () => {
  const second = procedure(0);
  delete second.procedure!.storedLocation;
  const index = new Map([[4, procedure(80)], [80, second]]);

  assert.match(analyzeCodeViewScopeChains(index).get(index.get(4)!)!, /unavailable segment/);
});

void test("Scope helpers distinguish inline/procedure ID ends and ordinary blocks", () => {
  const block: LegacyCodeViewSymbol = { type: 0x1103, data: { kind: "block", codeLength: 12,
    location: { segment: 1, offset: 24 }, scopeOffsets: { parent: 4, end: 96 } } };

  assert.equal(codeViewScopeEndType({ type: 0x114d, scope: { kind: "inline" } }), 0x114e);
  assert.equal(codeViewScopeEndType({ type: 0x1147, procedure: { referenceKind: "procedureId" } }), 0x114f);
  assert.equal(codeViewScopeEndType(block), 6);
  assert.equal(codeViewScopeLinks(block)?.end, 96);
  assert.equal(codeViewScopeLength(block), 12);
  assert.equal(codeViewScopeLocation(block)?.offset, 24);
  assert.equal(isCodeViewCallable(block), false);
});
