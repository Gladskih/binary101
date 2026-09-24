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
