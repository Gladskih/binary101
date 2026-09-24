"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFunctionOverride } from "../../../../../analyzers/pe/dynamic-relocations/function-override.js";

// Windows SDK IMAGE_FUNCTION_OVERRIDE_* types and IMAGE_BASE_RELOCATION layout:
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h

const makePayload = (): DataView => {
  const view = new DataView(new ArrayBuffer(56));
  view.setUint32(0, 36, true); // One header, two RVAs, one 12-byte relocation block.
  view.setUint32(4, 0x1010, true); // OriginalRva.
  view.setUint32(8, 0, true); // BDDOffset is relative to the BDD region.
  view.setUint32(12, 8, true); // RvaSize is bytes, not a count.
  view.setUint32(16, 12, true); // BaseRelocSize.
  view.setUint32(20, 0x2010, true);
  view.setUint32(24, 0x3010, true);
  view.setUint32(28, 0x1000, true); // IMAGE_BASE_RELOCATION.VirtualAddress.
  view.setUint32(32, 12, true); // IMAGE_BASE_RELOCATION.SizeOfBlock.
  view.setUint16(36, 0x1010, true); // Type 1, offset 0x010.
  view.setUint16(38, 0x3020, true); // Type 3, offset 0x020.
  view.setUint32(40, 1, true); // IMAGE_BDD_INFO.Version.
  view.setUint32(44, 8, true); // BDDSize.
  view.setUint16(48, 0, true); // Left.
  view.setUint16(50, 1, true); // Right.
  view.setUint32(52, 1, true); // Value.
  return view;
};

void test("parseFunctionOverride decodes override RVAs, relocation blocks and BDD nodes", () => {
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(makePayload(), 0, 56, warnings);

  assert.deepEqual(fixup, {
    functions: [{ originalRva: 0x1010, bddOffset: 0,
      overridingRvas: [0x2010, 0x3010], baseRelocations: [{ pageRva: 0x1000,
        entries: [{ type: 1, offset: 0x010 }, { type: 3, offset: 0x020 }] }] }],
    bddInfos: [{ offset: 0, version: 1, nodes: [{ left: 0, right: 1, value: 1 }] }]
  });
  assert.deepEqual(warnings, []);
});

void test("parseFunctionOverride rejects a truncated RVA array", () => {
  const view = makePayload();
  view.setUint32(12, 0x100, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /RVA array/i.test(warning)));
});

void test("parseFunctionOverride rejects a relocation block outside its declared region", () => {
  const view = makePayload();
  view.setUint32(32, 16, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /relocation block/i.test(warning)));
});

void test("parseFunctionOverride reports a relocation RVA past the PE address space", () => {
  const view = makePayload();
  view.setUint32(28, 0xffff_ffe8, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions[0]?.baseRelocations[0]?.entries[1],
    { type: 3, offset: 0x020 });
  assert.ok(warnings.some(warning => warning.includes("exceeds the PE address space")));
});

void test("parseFunctionOverride accepts the largest possible relocation RVA", () => {
  const view = makePayload();
  view.setUint32(28, 0xffff_ffef, true);
  view.setUint16(38, 0, true); // The second entry must not exceed the RVA limit.
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.equal(fixup?.functions[0]?.baseRelocations[0]?.pageRva, 0xffff_ffef);
  assert.deepEqual(warnings, []);
});

void test("parseFunctionOverride rejects a BDD offset that does not name a BDD record", () => {
  const view = makePayload();
  view.setUint32(8, 4, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /BDDOffset/i.test(warning)));
});

void test("parseFunctionOverride handles truncated BDD payload without throwing", () => {
  const view = makePayload();
  view.setUint32(44, 100, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.bddInfos, []);
  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /BDD/i.test(warning)));
});

void test("parseFunctionOverride rejects an out-of-range fixup span", () => {
  const warnings: string[] = [];

  assert.equal(parseFunctionOverride(makePayload(), -1, 56, warnings), null);
  assert.ok(warnings.some(warning => /fixup header/.test(warning)));
});

void test("parseFunctionOverride rejects a function region larger than the fixup", () => {
  const view = makePayload();
  view.setUint32(0, 100, true);
  const warnings: string[] = [];

  assert.equal(parseFunctionOverride(view, 0, 56, warnings), null);
  assert.ok(warnings.some(warning => /FuncOverrideSize/.test(warning)));
});

void test("parseFunctionOverride rejects a short function record header", () => {
  const view = makePayload();
  view.setUint32(0, 4, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /function record header/.test(warning)));
});

void test("parseFunctionOverride rejects a misaligned RVA array", () => {
  const view = makePayload();
  view.setUint32(12, 5, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /RVA array/.test(warning)));
});

void test("parseFunctionOverride rejects a truncated base relocation header", () => {
  const view = makePayload();
  view.setUint32(0, 28, true); // 16-byte record, 8 bytes of RVAs, 4-byte relocation region.
  view.setUint32(16, 4, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /relocation block header/.test(warning)));
});

void test("parseFunctionOverride rejects a truncated relocation region", () => {
  const view = makePayload();
  view.setUint32(16, 16, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.functions, []);
  assert.ok(warnings.some(warning => /relocation region/.test(warning)));
});

void test("parseFunctionOverride rejects a BDD with an incomplete node", () => {
  const view = makePayload();
  view.setUint32(44, 5, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

  assert.deepEqual(fixup?.bddInfos, []);
  assert.ok(warnings.some(warning => /incomplete node/.test(warning)));
});

void test("parseFunctionOverride preserves an unsupported BDD version with a warning", () => {
  const view = makePayload();
  view.setUint32(40, 2, true);
  const warnings: string[] = [];

  const fixup = parseFunctionOverride(view, 0, 56, warnings);

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
