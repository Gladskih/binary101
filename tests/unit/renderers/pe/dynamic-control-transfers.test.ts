"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDynamicControlTransfers } from
  "../../../../renderers/pe/dynamic-control-transfers.js";
import type { PeImportParseResult } from "../../../../analyzers/pe/imports/index.js";

const linkedImports: PeImportParseResult = { thunkEntrySize: 8, entries: [{
  dll: "evil<script>.dll", originalFirstThunkRva: 0,
  timeDateStamp: 0, forwarderChain: 0, firstThunkRva: 0x2000,
  lookupSource: "iat-fallback", thunkTableTerminated: true,
  functions: [{ name: "A&B" }]
}] };

void test("renderDynamicControlTransfers shows instruction RVAs and transfer metadata", () => {
  const html = renderDynamicControlTransfers([
    { kind: "v1", symbol: 3n, baseRelocSize: 0, availableBytes: 0,
      controlTransfers: [{ kind: "import", rva: 0x1010,
        indirectCall: true, iatIndex: 17 }] },
    { kind: "v1", symbol: 4n, baseRelocSize: 0, availableBytes: 0,
      controlTransfers: [{ kind: "indirect", rva: 0x1020,
        indirectCall: false, rexWPrefix: true, cfgCheck: true }] },
    { kind: "v1", symbol: 5n, baseRelocSize: 0, availableBytes: 0,
      controlTransfers: [{ kind: "switch", rva: 0x1030, registerNumber: 9 }] }
  ]);

  assert.match(html, /Control-transfer fixups \(3\)/);
  assert.match(html, /0x00001010/);
  assert.match(html, /IAT index 17/);
  assert.match(html, /REX\.W, CFG check/);
  assert.match(html, /register 9/);
});

void test("renderDynamicControlTransfers escapes resolved import names", () => {
  const html = renderDynamicControlTransfers([{ kind: "v1", symbol: 3n,
    baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "import", rva: 0x1010, indirectCall: true,
      iatIndex: 17, importLink: { entryIndex: 0, functionIndex: 0 } }] }], linkedImports);

  assert.match(html, /IAT index 17, evil&lt;script&gt;\.dll!A&amp;B/);
  assert.doesNotMatch(html, /<script>/i);
});

void test("renderDynamicControlTransfers keeps an invalid import link numeric", () => {
  const html = renderDynamicControlTransfers([{ kind: "v1", symbol: 3n,
    baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "import", rva: 0x1010, indirectCall: true,
      iatIndex: 17, importLink: { entryIndex: 4, functionIndex: 0 } }] }], linkedImports);

  assert.match(html, /IAT index 17/);
  assert.doesNotMatch(html, /evil/);
});

void test("renderDynamicControlTransfers resolves ordinal imports", () => {
  const imports: PeImportParseResult = { ...linkedImports, entries: [{
    ...linkedImports.entries[0]!, functions: [{ ordinal: 42 }]
  }] };
  const html = renderDynamicControlTransfers([{ kind: "v1", symbol: 3n,
    baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "import", rva: 0x1010, indirectCall: false,
      iatIndex: 17, importLink: { entryIndex: 0, functionIndex: 0 } }] }], imports);

  assert.match(html, /branch<\/td><td>IAT index 17, evil&lt;script&gt;\.dll!#42/);
});

void test("renderDynamicControlTransfers omits names absent from the import table", () => {
  const imports: PeImportParseResult = { ...linkedImports, entries: [{
    ...linkedImports.entries[0]!, functions: [{}]
  }] };
  const entries = [{ kind: "v1" as const, symbol: 3n,
    baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "import" as const, rva: 0x1010,
      indirectCall: true, iatIndex: 17,
      importLink: { entryIndex: 0, functionIndex: 0 } }] }];

  const html = renderDynamicControlTransfers(entries, imports);

  assert.match(html, /IAT index 17/);
  assert.doesNotMatch(html, /evil/);
});

void test("renderDynamicControlTransfers skips entries without transfer records", () => {
  const html = renderDynamicControlTransfers([
    { kind: "v1", symbol: 7n, baseRelocSize: 0, availableBytes: 0 },
    { kind: "v1", symbol: 5n, baseRelocSize: 0, availableBytes: 0,
      controlTransfers: [{ kind: "switch", rva: 0x1030, registerNumber: 9 }] }
  ]);

  assert.match(html, /Control-transfer fixups \(1\)/);
  assert.match(html, /register 9/);
});

void test("renderDynamicControlTransfers describes ARM64 delayed imports", () => {
  const html = renderDynamicControlTransfers([{ kind: "v1", symbol: 8n,
    baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "arm64Import", rva: 0x1040, indirectCall: true,
      registerIndex: 9, delayImport: true, iatIndex: null }] }]);

  assert.match(html, /ARM64_KERNEL_IMPORT_CALL_TRANSFER/);
  assert.match(html, /BLR/);
  assert.match(html, /delay import/);
  assert.match(html, /register 9/);
});

void test("renderDynamicControlTransfers handles static imports and unflagged branches", () => {
  const html = renderDynamicControlTransfers([{ kind: "v1", symbol: 8n,
    baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "arm64Import", rva: 0x1040, indirectCall: false,
      registerIndex: 0, delayImport: false, iatIndex: 3 }] },
  { kind: "v1", symbol: 4n, baseRelocSize: 0, availableBytes: 0,
    controlTransfers: [{ kind: "indirect", rva: 0x1050, indirectCall: true,
      rexWPrefix: false, cfgCheck: false }] }]);

  assert.match(html, /BR/);
  assert.match(html, /static import, IAT index 3/);
  assert.match(html, /<td>call<\/td><td>-<\/td>/);
});

void test("renderDynamicControlTransfers omits an empty table", () => {
  assert.equal(renderDynamicControlTransfers([]), "");
  assert.equal(renderDynamicControlTransfers([{ kind: "v1", symbol: 3n,
    baseRelocSize: 0, availableBytes: 0 }]), "");
});

void test("renderDynamicControlTransfers limits large tables", () => {
  // The UI displays at most 512 rows per dense table.
  const controlTransfers = Array.from({ length: 513 }, (_, index) =>
    ({ kind: "switch" as const, rva: 0x1000 + index, registerNumber: 1 }));

  const html = renderDynamicControlTransfers([{ kind: "v1", symbol: 5n,
    baseRelocSize: 0, availableBytes: 0, controlTransfers }]);

  assert.match(html, /Control-transfer fixups \(513\)/);
  assert.match(html, /1 more fixups hidden/);
  assert.doesNotMatch(html, /0x00001200/);
});
