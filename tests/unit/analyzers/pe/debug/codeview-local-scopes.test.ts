import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeCodeViewLocalScopes } from "../../../../../analyzers/pe/debug/codeview-local-scopes.js";
import type { LegacyCodeViewSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";

const scopeData = (): LegacyCodeViewSymbols => ({ kind: "symbols", recordOffsets: [4, 48, 80, 112, 144], records: [
  { type: 0x1110, name: "function", procedure: { referenceKind: "typeIndex", codeLength: 64,
    storedLocation: { segment: 1, offset: 32 }, scopeOffsets: { parent: 0, end: 144, next: 0 } } },
  { type: 0x1012, frame: { frameBytes: 32, paddingBytes: 0, paddingOffset: 0, savedRegisterBytes: 0,
    handler: { section: 0, offset: 0 }, flags: 0 } },
  { type: 0x113e, name: "local", local: { typeIndex: 0x74, flags: 1 } },
  { type: 0x1142, localRange: { location: { kind: "frameRelative", offset: -8 },
    range: { section: 1, offset: 32, length: 64 }, gaps: [] } },
  { type: 6 }
] });

void test("CodeView links frames and consecutive ranges to a validated containing procedure", () => {
  const data = scopeData();
  const result = analyzeCodeViewLocalScopes(data);

  assert.equal(result.bindings.length, 3);
  assert.equal(result.bindings[0]?.procedure, data.records[0]);
  assert.equal(result.bindings[1]?.procedure, data.records[0]);
  assert.equal(result.bindings[2]?.local, data.records[2]);
  assert.deepEqual(result.bindings.map(binding => binding.issues), [[], [], []]);
  assert.deepEqual(result.issues, []);
});

for (const [field, value, reason] of [["end", 0, /not populated/], ["end", 112, /matching end/],
  ["parent", 112, /parent/], ["next", 112, /next/]] as const) {
  void test(`CodeView invalid scope ${field}=${value} does not fabricate a containing procedure`, () => {
    const data = scopeData();
    data.records[0]!.procedure!.scopeOffsets![field] = value;
    const result = analyzeCodeViewLocalScopes(data);

    assert.equal(result.bindings[0]?.procedure, undefined);
    assert.match(result.bindings[0]!.issues.join(" | "), reason);
  });
}

void test("CodeView does not attach a nonconsecutive range to the previous local", () => {
  const data = scopeData();
  data.records.splice(3, 0, { type: 0x1101, name: "separator" });
  data.recordOffsets!.splice(3, 0, 100);
  const result = analyzeCodeViewLocalScopes(data);

  assert.equal(result.bindings[2]?.local, undefined);
  assert.match(result.bindings[2]!.issues.join(" | "), /consecutive S_LOCAL/);
});

void test("CodeView range addresses must fit the containing procedure's stored segment and span", () => {
  const data = scopeData();
  data.records[3]!.localRange!.range!.offset = 31;
  const before = analyzeCodeViewLocalScopes(data);
  data.records[3]!.localRange!.range!.offset = 33;
  const after = analyzeCodeViewLocalScopes(data);
  data.records[3]!.localRange!.range!.section = 2;
  const segment = analyzeCodeViewLocalScopes(data);

  assert.match(before.bindings[2]!.issues.join(" | "), /outside.*procedure/);
  assert.match(after.bindings[2]!.issues.join(" | "), /outside.*procedure/);
  assert.match(segment.bindings[2]!.issues.join(" | "), /segment/);
});

void test("CodeView missing or corrupt source offsets retain metadata with an explicit unresolved scope", () => {
  const data = scopeData();
  delete data.recordOffsets;
  const absent = analyzeCodeViewLocalScopes(data);
  data.recordOffsets = [4];
  const short = analyzeCodeViewLocalScopes(data);

  assert.equal(absent.bindings.length, 3);
  assert.equal(absent.bindings[0]?.procedure, undefined);
  assert.match(absent.bindings[0]!.issues.join(" | "), /offsets/);
  assert.match(short.bindings[0]!.issues.join(" | "), /offsets/);
});

void test("Procedure-ID scopes require their own end kind", () => {
  const data = scopeData();
  data.records[0]!.procedure!.referenceKind = "procedureId";
  assert.equal(analyzeCodeViewLocalScopes(data).bindings[0]?.procedure, undefined);
  data.records[4]!.type = 0x114f;

  assert.equal(analyzeCodeViewLocalScopes(data).bindings[0]?.procedure, data.records[0]);
});

for (const field of ["storedLocation", "codeLength"] as const) {
  void test(`Range validation does not guess missing procedure ${field}`, () => {
    const data = scopeData();
    delete data.records[0]!.procedure![field];

    assert.match(analyzeCodeViewLocalScopes(data).bindings[2]!.issues.join(" | "), /address fields are unavailable/);
  });
}

void test("Compiler records with absent links and a root block keep metadata unresolved", () => {
  const data = scopeData();
  delete data.records[0]!.procedure!.scopeOffsets;
  assert.match(analyzeCodeViewLocalScopes(data).bindings[0]!.issues.join(" | "), /not populated/);
  data.records[0] = { type: 0x1103, data: { kind: "block", scopeOffsets: { parent: 0, end: 144 } } };

  assert.match(analyzeCodeViewLocalScopes(data).bindings[0]!.issues.join(" | "), /No validated containing procedure/);
});

void test("Child scopes cannot extend through their parent end", () => {
  const data = scopeData();
  data.records.splice(2, 0, { type: 0x1103, data: { kind: "block", scopeOffsets: { parent: 4, end: 144 } } });
  data.recordOffsets!.splice(2, 0, 60);

  assert.match(analyzeCodeViewLocalScopes(data).bindings[1]!.issues.join(" | "), /outside.*parent/);
});

void test("Child scopes inherit uncertainty from an unlinked parent", () => {
  const data = scopeData();
  data.records[0]!.procedure!.scopeOffsets!.end = 0;
  data.records.splice(2, 0, { type: 0x1103, data: { kind: "block", scopeOffsets: { parent: 4, end: 128 } } });
  data.recordOffsets!.splice(2, 0, 60);
  data.records.splice(5, 0, { type: 6 });
  data.recordOffsets!.splice(5, 0, 128);

  assert.match(analyzeCodeViewLocalScopes(data).bindings[1]!.issues.join(" | "), /Containing scope/);
});

for (const [type, end] of [[0x114d, 0x114e], [0x1102, 6]]) {
  void test(`Unsupported scope kind ${type} blocks attribution until its own end`, () => {
    const data = scopeData();
    data.records.splice(2, 0, { type: type! }, { type: 0x113e, name: "inner", local: { typeIndex: 1 } }, { type: end! });
    data.recordOffsets!.splice(2, 0, 60, 68, 76);
    const result = analyzeCodeViewLocalScopes(data);

    assert.equal(result.bindings[1]?.procedure, undefined);
    assert.match(result.bindings[1]!.issues.join(" | "), /Unsupported enclosing scope/);
    assert.equal(result.bindings[2]?.procedure, data.records[0]);
  });
}

void test("Scope end diagnostics distinguish orphan, wrong-kind and unclosed scopes", () => {
  const orphan = analyzeCodeViewLocalScopes({ kind: "symbols", recordOffsets: [4], records: [{ type: 6 }] });
  const data = scopeData();
  data.records[4]!.type = 0x114e;
  const wrong = analyzeCodeViewLocalScopes(data);
  data.records.pop();
  data.recordOffsets!.pop();
  const unclosed = analyzeCodeViewLocalScopes(data);

  assert.match(orphan.issues.join(" | "), /no matching opening/);
  assert.match(wrong.issues.join(" | "), /wrong kind/);
  assert.match(unclosed.issues.join(" | "), /unclosed/);
});

void test("A later root procedure recovers after an unclosed malformed predecessor", () => {
  const data = scopeData();
  data.records.pop();
  data.recordOffsets!.pop();
  data.records.push({ type: 0x1110, name: "second", procedure: { referenceKind: "typeIndex",
    scopeOffsets: { parent: 0, end: 240, next: 0 } } }, { ...data.records[1]! }, { type: 6 });
  data.recordOffsets!.push(160, 200, 240);
  const result = analyzeCodeViewLocalScopes(data);

  assert.equal(result.bindings.at(-1)?.procedure?.name, "second");
  assert.match(result.issues.join(" | "), /preceding scope closes/);
});

void test("Optimized-out and seeded location records remain diagnostic rather than ordinary lifetimes", () => {
  const data = scopeData();
  data.records[2]!.local!.flags = 0x100;
  data.records[3]!.localRange!.range!.length = 0xf000;

  assert.match(analyzeCodeViewLocalScopes(data).bindings[2]!.issues.join(" | "), /optimized-out/);
  assert.match(analyzeCodeViewLocalScopes(data).bindings[2]!.issues.join(" | "), /Reserved local-range/);
});

void test("An unexpected early scope end is diagnosed and does not leak attribution to later locals", () => {
  const data = scopeData();
  data.records.splice(2, 0, { type: 6 });
  data.recordOffsets!.splice(2, 0, 60);
  const result = analyzeCodeViewLocalScopes(data);

  assert.equal(result.bindings[1]?.procedure, undefined);
  assert.match(result.issues.join(" | "), /different offset/);
});

void test("Scope links cannot point to a real end record before their opening record", () => {
  const data = scopeData();
  data.records.unshift({ type: 6 });
  data.recordOffsets!.unshift(2);
  data.records[1]!.procedure!.scopeOffsets!.end = 2;

  assert.equal(analyzeCodeViewLocalScopes(data).bindings[0]?.procedure, undefined);
});

void test("A valid nested block inherits the containing procedure until its own end", () => {
  const data = scopeData();
  data.records.splice(2, 0, { type: 0x1103, data: { kind: "block", scopeOffsets: { parent: 4, end: 128 } } });
  data.recordOffsets!.splice(2, 0, 60);
  data.records.splice(5, 0, { type: 6 });
  data.recordOffsets!.splice(5, 0, 128);
  const result = analyzeCodeViewLocalScopes(data);

  assert.equal(result.bindings[1]?.procedure, data.records[0]);
  assert.deepEqual(result.issues, []);
});

void test("A next link may name another procedure but cannot point to itself", () => {
  const data = scopeData();
  data.records.push({ type: 0x1110, name: "second", procedure: { referenceKind: "typeIndex",
    scopeOffsets: { parent: 0, end: 240, next: 0 } } }, { ...data.records[1]! }, { type: 6 });
  data.recordOffsets!.push(160, 200, 240);
  data.records[0]!.procedure!.scopeOffsets!.next = 160;
  assert.deepEqual(analyzeCodeViewLocalScopes(data).issues, []);
  data.records[0]!.procedure!.scopeOffsets!.next = 4;
  assert.equal(analyzeCodeViewLocalScopes(data).bindings[0]?.procedure, undefined);
});
