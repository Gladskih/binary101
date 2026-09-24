"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
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
