import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeTd32SymbolLinks } from "../../../../../analyzers/pe/debug/td32-symbol-links.js";
import type { Td32Symbols } from "../../../../../analyzers/pe/debug/td32-symbols.js";

const scopes = (): Td32Symbols => ({ kind: "symbols", recordOffsets: [4, 48, 52, 96], records: [
  { type: 0x205, nameIndex: 1, metadata: { location: { segment: 1, offset: 32 },
    scopeOffsets: { parent: 0, end: 48, next: 0 } } }, { type: 6 },
  { type: 0x204, nameIndex: 2, metadata: { location: { segment: 1, offset: 64 },
    scopeOffsets: { parent: 4, end: 96, next: 0 } } }, { type: 6 }] });

void test("TD32 parent links resolve nested procedures even when their records are stream siblings", () => {
  const data = scopes();
  const result = analyzeTd32SymbolLinks(data);

  assert.deepEqual(result.get(data.records[2]!), { parent: data.records[0], issues: [] });
  assert.deepEqual(result.get(data.records[0]!), { issues: [] });
});

void test("TD32 scope graphs diagnose cycles without recursively walking attacker-controlled depth", () => {
  const data = scopes();
  data.records[0]!.metadata!.scopeOffsets!.parent = 52;
  data.records[0]!.metadata!.scopeOffsets!.next = 52;
  data.records[2]!.metadata!.scopeOffsets!.next = 4;
  const result = analyzeTd32SymbolLinks(data);

  assert.match(result.get(data.records[0]!)!.issues.join(" | "), /parent cycle.*next cycle/);
  assert.equal(result.get(data.records[2]!)!.parent, undefined);
});

void test("TD32 scope links expose unavailable physical offsets without inventing parents", () => {
  const data = scopes();
  delete data.recordOffsets;

  assert.match(analyzeTd32SymbolLinks(data).get(data.records[0]!)!.issues.join(" | "), /Physical symbol offsets/);
  data.recordOffsets = [4];
  assert.equal(analyzeTd32SymbolLinks(data).size, 2);
  data.recordOffsets = [4, 48, 4, 96];
  assert.equal(analyzeTd32SymbolLinks(data).size, 2);
});

void test("TD32 scope links diagnose unpopulated ends, wrong target kinds and missing parents", () => {
  const data = scopes();
  data.records[0]!.metadata!.scopeOffsets = { parent: 999, end: 0, next: 48 };
  data.records[2]!.metadata!.scopeOffsets!.end = 48;
  const result = analyzeTd32SymbolLinks(data);

  assert.match(result.get(data.records[0]!)!.issues.join(" | "), /not populated.*parent link.*next link/);
  assert.match(result.get(data.records[2]!)!.issues.join(" | "), /following END/);
});

void test("TD32 missing and cross-segment next targets remain diagnostic", () => {
  const data = scopes();
  data.records[0]!.metadata!.scopeOffsets!.next = 999;
  assert.match(analyzeTd32SymbolLinks(data).get(data.records[0]!)!.issues.join(" | "), /next link/);
  data.records[0]!.metadata!.scopeOffsets!.next = 52;
  data.records[2]!.metadata!.location!.segment = 2;
  assert.match(analyzeTd32SymbolLinks(data).get(data.records[0]!)!.issues.join(" | "), /crosses segments/);
});

void test("TD32 acyclic components can share a previously visited parent and next tail", () => {
  const data = scopes();
  data.records[0]!.metadata!.scopeOffsets!.next = 52;
  data.records.push({ type: 0x204, metadata: { scopeOffsets: { parent: 4, end: 144, next: 52 },
    location: { segment: 1, offset: 80 } } }, { type: 6 });
  data.recordOffsets!.push(100, 144);

  assert.ok([...analyzeTd32SymbolLinks(data).values()].every(value => value.issues.length === 0));
});

void test("TD32 next targets require decoded scope and segment fields", () => {
  const data = scopes();
  data.records[0]!.metadata!.scopeOffsets!.next = 52;
  delete data.records[2]!.metadata;
  assert.match(analyzeTd32SymbolLinks(data).get(data.records[0]!)!.issues.join(" | "), /unavailable scope/);
  data.records[2]!.metadata = { scopeOffsets: { parent: 0, end: 96, next: 0 } };
  assert.match(analyzeTd32SymbolLinks(data).get(data.records[0]!)!.issues.join(" | "), /unavailable segment/);
});
