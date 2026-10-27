import assert from "node:assert/strict";
import { test } from "node:test";
import { collectEhLoadConfigChecks } from "../../../../../analyzers/pe/msvc-eh/checks.js";
import { createPeLoadConfigResult } from "../../../../../analyzers/pe/load-config/result.js";
import type { MsvcEhAnalysis } from "../../../../../analyzers/pe/msvc-eh/types.js";

const analysis: MsvcEhAnalysis = { warnings: [], records: [{ unwindInfoRva: 1,
  handlerRva: 2, evidence: "import", functionRvas: [0x1000], functionInfo: {
    rva: 0x2000, version: 4, unwindActions: [], ipStates: [],
    tryBlocks: [{ tryLow: 0, tryHigh: 0, catchHigh: 1, handlers: [
      { handlerRva: 0x1100, typeDescriptorRva: 0, continuationRvas: [0x1010] }
    ] }]
  } }] };

void test("EH continuation mismatch belongs to Load Config checks", () => {
  const lc = createPeLoadConfigResult();
  lc.Size = 0x118; // PE32+ Load Config through GuardEHContinuationCount.
  lc.GuardFlags = 0x00400000; // PE IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT.
  const checks = collectEhLoadConfigChecks(lc, analysis, 0);
  assert.equal(checks[0]?.status, "fail");
  assert.match(checks[0]?.detail ?? "", /0x1010/);
  assert.equal(checks[0]?.title, "Microsoft EH continuation targets");
  assert.equal(checks[0]?.source,
    "https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata");
});

void test("NO_SEH contradicts proven EH even without a SafeSEH table", () => {
  const checks = collectEhLoadConfigChecks(createPeLoadConfigResult(), analysis, 0x0400);
  assert.equal(checks[0]?.status, "fail");
  assert.match(checks[0]?.title ?? "", /NO_SEH/);
  assert.match(checks[0]?.detail ?? "", /NO_SEH.*validated Microsoft-compatible/);
});

void test("legacy image without EHCONT is not called inconsistent", () => {
  assert.deepEqual(collectEhLoadConfigChecks(createPeLoadConfigResult(), analysis, 0), []);
});

void test("a complete advertised table proves explicit continuation membership", () => {
  const lc = createPeLoadConfigResult();
  lc.Size = 0x118;
  lc.GuardFlags = 0x00400000;
  lc.GuardEHContinuationCount = 1;
  lc.tables = { guardEhContinuation: { name: "EHCONT", kind: "guardEhContinuation",
    tableVa: 0n, tableRva: 0x2000, entrySize: 4, declaredCount: 1,
    entries: [{ index: 0, rva: 0x1010 }], truncated: false } };
  const checks = collectEhLoadConfigChecks(lc, analysis, 0);
  assert.equal(checks[0]?.status, "pass");
  assert.match(checks[0]?.detail ?? "", /1 explicit EH continuation target/);
});

void test("missing and truncated advertised tables produce uncertainty rather than a missing-target claim", () => {
  const lc = createPeLoadConfigResult();
  lc.Size = 0x118;
  lc.GuardFlags = 0x00400000;
  lc.GuardEHContinuationCount = 1;
  const checks = collectEhLoadConfigChecks(lc, analysis, 0);
  assert.equal(checks[0]?.status, "info");
  assert.equal(checks[0]?.title, "Microsoft EH continuation cross-check");
  assert.match(checks[0]?.detail ?? "", /incomplete.*cannot be established/);
  lc.tables = { guardEhContinuation: { name: "EHCONT", kind: "guardEhContinuation",
    tableVa: 0n, tableRva: 0x2000, entrySize: 4, declaredCount: 1,
    entries: [{ index: 0, rva: 0x1010 }], truncated: true } };
  assert.equal(collectEhLoadConfigChecks(lc, analysis, 0)[0]?.status, "info");
});

void test("SEH targets are cross-checked while finally handlers are excluded", () => {
  const lc = createPeLoadConfigResult();
  lc.Size = 0x118;
  lc.GuardFlags = 0x00400000;
  const checks = collectEhLoadConfigChecks(lc, { warnings: [], records: [{
    handlerRva: 0x1000, scopeTableRva: 0x2000, evidence: "export", functionRvas: [0x1000],
    scopes: [{ beginRva: 0x1000, endRva: 0x1010, filterRva: 1, targetRva: 0x1020 },
      { beginRva: 0x1000, endRva: 0x1010, filterRva: 0x1100, targetRva: 0 }]
  }] }, 0);
  assert.match(checks[0]?.detail ?? "", /0x1020/);
  assert.doesNotMatch(checks[0]?.detail ?? "", /0x1100/);
  assert.deepEqual(collectEhLoadConfigChecks(lc, { records: [], warnings: [] }, 0x0400), []);
});

void test("unread EHCONT count fields do not become a supposedly confirmed empty table", () => {
  const lc = createPeLoadConfigResult();
  lc.GuardFlags = 0x00400000;
  assert.equal(collectEhLoadConfigChecks(lc, analysis, 0)[0]?.status, "info");
  lc.Size = 0x118;
  lc.warnings = ["GuardEHContinuationCount exceeds the supported safe integer range."];
  assert.equal(collectEhLoadConfigChecks(lc, analysis, 0)[0]?.status, "info");
});

for (const [count, declared, entries] of [[2, 2, [0x1010]], [1, 2, [0x1010]]] as const) {
  void test(`EHCONT completeness checks both count fields ${count}/${declared}`, () => {
    const lc = createPeLoadConfigResult();
    lc.Size = 0x118;
    lc.GuardFlags = 0x00400000;
    lc.GuardEHContinuationCount = count;
    lc.tables = { guardEhContinuation: { name: "EHCONT", kind: "guardEhContinuation",
      tableVa: 0n, tableRva: 0x2000, entrySize: 4, declaredCount: declared, truncated: false,
      entries: entries.map((rva, index) => ({ rva, index })) } };
    assert.equal(collectEhLoadConfigChecks(lc, analysis, 0)[0]?.status, "info");
  });
}

for (const [pointerSize, incompleteSize, completeSize] of [[4, 0xa0, 0xac], [8, 0x110, 0x118]] as const) {
  void test(`EHCONT needs the whole ${pointerSize}-byte count field`, () => {
    const lc = createPeLoadConfigResult();
    lc.GuardFlags = 0x00400000;
    lc.Size = incompleteSize;
    assert.equal(collectEhLoadConfigChecks(lc, analysis, 0, pointerSize)[0]?.status, "info");
    lc.Size = completeSize;
    assert.equal(collectEhLoadConfigChecks(lc, analysis, 0, pointerSize)[0]?.status, "fail");
  });
}
