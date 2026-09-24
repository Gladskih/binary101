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
