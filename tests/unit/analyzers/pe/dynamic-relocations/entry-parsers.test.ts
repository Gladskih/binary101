"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseDynamicRelocationEntriesV132,
  parseDynamicRelocationEntriesV232,
  parseDynamicRelocationEntriesV264
} from "../../../../../analyzers/pe/dynamic-relocations/entry-parsers.js";

for (const [name, headerSize, parser] of [
  ["PE32", 20, parseDynamicRelocationEntriesV232],
  ["PE32+", 24, parseDynamicRelocationEntriesV264]
] as const) {
  void test(`${name} V2 rejects a header beyond the table when payload size is zero`, () => {
    const bytes = new Uint8Array(8 + headerSize);
    const view = new DataView(bytes.buffer);
    view.setUint32(8, headerSize + 4, true);
    view.setUint32(12, 0, true);
    const warnings: string[] = [];

    const entries = parser(view, bytes.byteLength, warnings);

    assert.equal(entries.length, 0);
    assert.ok(warnings.some(warning => /header.*truncated/i.test(warning)));
  });
}

void test("V1 exposes import control transfers from a relocation block", () => {
  const view = new DataView(new ArrayBuffer(8 + 8 + 12));
  view.setUint32(8, 3, true); // GUARD_IMPORT_CONTROL_TRANSFER.
  view.setUint32(12, 12, true);
  view.setUint32(16, 0x1000, true);
  view.setUint32(20, 12, true);
  view.setUint32(24, 0x123 | (7 << 13), true);
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV132(view, view.byteLength, warnings);

  assert.deepEqual(entries[0]?.controlTransfers,
    [{ kind: "import", rva: 0x1123, indirectCall: false, iatIndex: 7 }]);
  assert.deepEqual(warnings, []);
});

void test("V2 exposes indirect control transfers from a relocation block", () => {
  const view = new DataView(new ArrayBuffer(8 + 24 + 10));
  view.setUint32(8, 24, true);
  view.setUint32(12, 10, true);
  view.setBigUint64(16, 4n, true); // GUARD_INDIR_CONTROL_TRANSFER.
  view.setUint32(32, 0x2000, true);
  view.setUint32(36, 10, true);
  view.setUint16(40, 0x345, true);
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV264(view, view.byteLength, warnings);

  assert.deepEqual(entries[0]?.controlTransfers,
    [{ kind: "indirect", rva: 0x2345, indirectCall: false,
      rexWPrefix: false, cfgCheck: false }]);
  assert.deepEqual(warnings, []);
});

void test("PE32+ V2 decodes a complete function override fixup", () => {
  const view = new DataView(new ArrayBuffer(8 + 24 + 12));
  view.setUint32(8, 24, true); // V2 fixed header size.
  view.setUint32(12, 12, true); // Function override header plus empty BDD.
  view.setBigUint64(16, 7n, true); // IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE.
  view.setUint32(32, 0, true); // FuncOverrideSize.
  view.setUint32(36, 1, true); // BDD version.
  view.setUint32(40, 0, true); // BDDSize.
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV264(view, view.byteLength, warnings);

  assert.deepEqual(entries[0]?.fixup, {
    functions: [], bddInfos: [{ offset: 0, version: 1, nodes: [] }]
  });
  assert.deepEqual(warnings, []);
});

void test("V2 does not use incomplete Function Override data", () => {
  const view = new DataView(new ArrayBuffer(8 + 24 + 4));
  view.setUint32(8, 24, true);
  view.setUint32(12, 12, true); // More fixup bytes declared than available.
  view.setBigUint64(16, 7n, true);
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV264(view, view.byteLength, warnings);

  assert.equal(entries[0]?.fixup, undefined);
  assert.ok(warnings.some(warning => /FixupInfoSize/.test(warning)));
});

void test("V2 does not decode a Function Override behind an undersized header", () => {
  const view = new DataView(new ArrayBuffer(8 + 24 + 12));
  view.setUint32(8, 4, true); // Smaller than the fixed PE32+ V2 header.
  view.setUint32(12, 12, true);
  view.setBigUint64(16, 7n, true);
  view.setUint32(32, 0, true);
  view.setUint32(36, 1, true);
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV264(view, view.byteLength, warnings);

  assert.equal(entries[0]?.fixup, undefined);
  assert.ok(warnings.some(warning => /smaller than the fixed/.test(warning)));
});

void test("PE32+ V2 passes Guard RF variable header and fixup info to decoder", () => {
  const view = new DataView(new ArrayBuffer(8 + 24 + 3 + 10));
  view.setUint32(8, 27, true); // Fixed V2 header plus 3-byte prologue header.
  view.setUint32(12, 10, true);
  view.setBigUint64(16, 1n, true); // Guard RF prologue.
  view.setUint8(32, 2);
  view.setUint8(33, 0x90);
  view.setUint8(34, 0xcc);
  view.setUint32(35, 0x1000, true);
  view.setUint32(39, 10, true);
  view.setUint16(43, 0x123, true);
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV264(view, view.byteLength, warnings);

  assert.deepEqual(entries[0]?.guardRf, { kind: "prologue", prologueBytes: [0x90, 0xcc],
    sites: [{ rva: 0x1123, type: 0 }] });
  assert.deepEqual(warnings, []);
});

void test("PE32 V1 decodes ARM64X fixup blocks", () => {
  const view = new DataView(new ArrayBuffer(8 + 8 + 12));
  view.setUint32(8, 6, true); // ARM64X.
  view.setUint32(12, 12, true);
  view.setUint32(16, 0x3000, true);
  view.setUint32(20, 12, true);
  view.setUint16(24, 0x4100, true); // Two-byte zero fill.
  const warnings: string[] = [];

  const entries = parseDynamicRelocationEntriesV132(view, view.byteLength, warnings);

  assert.deepEqual(entries[0]?.arm64xFixups,
    [{ kind: "zeroFill", rva: 0x3100, size: 2 }]);
  assert.deepEqual(warnings, []);
});
