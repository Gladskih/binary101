"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFunctionOverride } from "../../../../../analyzers/pe/dynamic-relocations/function-override.js";

const makePayload = (): DataView => {
  const view = new DataView(new ArrayBuffer(52));
  view.setUint32(0, 32, true); // FuncOverrideSize: one 16-byte header, two RVAs, one 8-byte relocation block.
  view.setUint32(4, 0x1010, true); // OriginalRva.
  view.setUint32(8, 0, true); // BDDOffset is relative to the BDD region.
  view.setUint32(12, 8, true); // RvaSize is bytes, not a count.
  view.setUint32(16, 8, true); // BaseRelocSize.
  view.setUint32(20, 0x2010, true);
  view.setUint32(24, 0x3010, true);
  view.setUint32(28, 0x1000, true); // IMAGE_BASE_RELOCATION.VirtualAddress.
  view.setUint32(32, 8, true); // IMAGE_BASE_RELOCATION.SizeOfBlock.
  view.setUint32(36, 1, true); // IMAGE_BDD_INFO.Version.
  view.setUint32(40, 8, true); // BDDSize.
  view.setUint16(44, 0, true); // Left.
  view.setUint16(46, 1, true); // Right.
  view.setUint32(48, 1, true); // Value.
  return view;
};

void test("parseFunctionOverride decodes override RVAs, relocation blocks and BDD nodes", () => {
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(makePayload(), 0, 52, warnings);

  assert.deepEqual(fixup, {
    functions: [{ originalRva: 0x1010, bddOffset: 0,
      overridingRvas: [0x2010, 0x3010], baseRelocations: [{ pageRva: 0x1000, typeOffsets: [] }] }],
    bddInfos: [{ offset: 0, version: 1, nodes: [{ left: 0, right: 1, value: 1 }] }]
  });
  assert.deepEqual(warnings, []);
});

void test("parseFunctionOverride rejects a truncated RVA array", () => {
  const view = makePayload();
  view.setUint32(12, 0x100, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /RVA array/i.test(warning)));
});

void test("parseFunctionOverride rejects a relocation block outside its declared region", () => {
  const view = makePayload();
  view.setUint32(32, 12, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /relocation block/i.test(warning)));
});

void test("parseFunctionOverride rejects a BDD offset that does not name a BDD record", () => {
  const view = makePayload();
  view.setUint32(8, 4, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /BDDOffset/i.test(warning)));
});

void test("parseFunctionOverride handles truncated BDD payload without throwing", () => {
  const view = makePayload();
  view.setUint32(40, 100, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.bddInfos, []);
  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /BDD/i.test(warning)));
});

void test("parseFunctionOverride rejects an out-of-range fixup span", () => {
  const warnings: string[] = [];

  assert.equal(parseFunctionOverride(makePayload(), -1, 52, warnings), null);
  assert.ok(warnings.some(warning => /fixup header/.test(warning)));
});

void test("parseFunctionOverride rejects a function region larger than the fixup", () => {
  const view = makePayload();
  view.setUint32(0, 100, true);
  const warnings: string[] = [];

  assert.equal(parseFunctionOverride(view, 0, 52, warnings), null);
  assert.ok(warnings.some(warning => /FuncOverrideSize/.test(warning)));
});

void test("parseFunctionOverride rejects a short function record header", () => {
  const view = makePayload();
  view.setUint32(0, 4, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /function record header/.test(warning)));
});

void test("parseFunctionOverride rejects a misaligned RVA array", () => {
  const view = makePayload();
  view.setUint32(12, 5, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /RVA array/.test(warning)));
});

void test("parseFunctionOverride rejects a truncated base relocation header", () => {
  const view = makePayload();
  view.setUint32(0, 28, true); // 16-byte record, 8 bytes of RVAs, 4-byte relocation region.
  view.setUint32(16, 4, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /relocation block header/.test(warning)));
});

void test("parseFunctionOverride rejects a truncated relocation region", () => {
  const view = makePayload();
  view.setUint32(16, 16, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /relocation region/.test(warning)));
});

void test("parseFunctionOverride rejects a BDD with an incomplete node", () => {
  const view = makePayload();
  view.setUint32(40, 5, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.bddInfos, []);
  assert.ok(warnings.some(warning => /incomplete node/.test(warning)));
});

void test("parseFunctionOverride preserves an unsupported BDD version with a warning", () => {
  const view = makePayload();
  view.setUint32(36, 2, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 52, warnings);

  assert.deepEqual(fixup?.bddInfos, [{ offset: 0, version: 2, nodes: [] }]);
  assert.ok(warnings.some(warning => /unsupported BDD version 2/.test(warning)));
});

void test("parseFunctionOverride resolves offsets for multiple BDD records", () => {
  const view = new DataView(new ArrayBuffer(60));
  view.setUint32(0, 40, true); // Two function records of 20 bytes each.
  view.setUint32(4, 0x1010, true);
  view.setUint32(8, 0, true);
  view.setUint32(12, 4, true);
  view.setUint32(20, 0x2010, true);
  view.setUint32(24, 0x3010, true);
  view.setUint32(28, 8, true); // Second BDD begins eight bytes into BDD region.
  view.setUint32(32, 4, true);
  view.setUint32(40, 0x4010, true);
  view.setUint32(44, 1, true);
  view.setUint32(52, 1, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 60, warnings);

  assert.deepEqual(fixup?.functions.map(record => record.overridingRvas),
    [[0x2010], [0x4010]]);
  assert.deepEqual(fixup?.bddInfos.map(info => info.offset), [0, 8]);
  assert.deepEqual(warnings, []);
});
