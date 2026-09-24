"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseControlTransfers } from
  "../../../../../analyzers/pe/dynamic-relocations/control-transfers.js";

const block = (entrySize: 2 | 4, value: number): DataView => {
  const view = new DataView(new ArrayBuffer(8 + entrySize));
  view.setUint32(0, 0x1000, true); // IMAGE_BASE_RELOCATION.VirtualAddress.
  view.setUint32(4, 8 + entrySize, true); // SizeOfBlock.
  if (entrySize === 4) view.setUint32(8, value, true);
  else view.setUint16(8, value, true);
  return view;
};

void test("parseControlTransfers decodes x64 import calls and IAT indices", () => {
  // winnt.h: 12-bit page offset, one call bit, 19-bit IAT index.
  const view = block(4, 0x123 | (1 << 12) | (0x12345 << 13));
  const warnings: string[] = [];

  const records = parseControlTransfers(view, 0, view.byteLength, 3n, warnings);

  assert.deepEqual(records, [{ kind: "import", rva: 0x1123,
    indirectCall: true, iatIndex: 0x12345 }]);
  assert.deepEqual(warnings, []);
});

void test("parseControlTransfers decodes indirect transfer flags", () => {
  // winnt.h: bit 12 call, bit 13 REX.W, bit 14 CFG check.
  const view = block(2, 0x234 | (1 << 12) | (1 << 13) | (1 << 14));
  const warnings: string[] = [];

  const records = parseControlTransfers(view, 0, view.byteLength, 4n, warnings);

  assert.deepEqual(records, [{ kind: "indirect", rva: 0x1234,
    indirectCall: true, rexWPrefix: true, cfgCheck: true }]);
  assert.deepEqual(warnings, []);
});

void test("parseControlTransfers decodes switch register numbers", () => {
  // winnt.h: 12-bit page offset followed by four register bits.
  const view = block(2, 0x345 | (7 << 12));
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 5n, warnings),
    [{ kind: "switch", rva: 0x1345, registerNumber: 7 }]);
  assert.deepEqual(warnings, []);
});

void test("parseControlTransfers decodes ARM64 import transfers with scaled offsets", () => {
  // winnt.h: ARM64 offset is ten bits and names a four-byte instruction.
  const view = block(4, 0x155 | (1 << 10) | (9 << 11) | (1 << 16) | (42 << 17));
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 8n, warnings),
    [{ kind: "arm64Import", rva: 0x1554, indirectCall: true,
      registerIndex: 9, delayImport: true, iatIndex: 42 }]);
  assert.deepEqual(warnings, []);
});

void test("parseControlTransfers rejects malformed block sizes", () => {
  const view = block(4, 0);
  view.setUint32(4, 0, true);
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 3n, warnings), []);
  assert.ok(warnings.some(warning => /block size/.test(warning)));
});

void test("parseControlTransfers rejects incomplete records and unaligned pages", () => {
  const view = block(4, 0);
  view.setUint32(0, 0x1001, true);
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 3n, warnings), []);
  assert.ok(warnings.some(warning => /page RVA/.test(warning)));
});

void test("parseControlTransfers rejects incomplete block headers", () => {
  const view = new DataView(new ArrayBuffer(4));
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 3n, warnings), []);
  assert.ok(warnings.some(warning => /block header/.test(warning)));
});

void test("parseControlTransfers rejects a block with partial records", () => {
  const view = new DataView(new ArrayBuffer(10));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 10, true); // An x64 import record needs four bytes after the block header.
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 3n, warnings), []);
  assert.ok(warnings.some(warning => /block size/.test(warning)));
});

void test("parseControlTransfers rejects the reserved indirect transfer bit", () => {
  const view = block(2, 0x8001);
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 4n, warnings), []);
  assert.ok(warnings.some(warning => /reserved bit/.test(warning)));
});

void test("parseControlTransfers treats the ARM64 IAT sentinel as unavailable", () => {
  // winnt.h: ARM64 IATIndex 0x7fff means no index.
  const view = block(4, 0x7fff << 17);
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(view, 0, view.byteLength, 8n, warnings),
    [{ kind: "arm64Import", rva: 0x1000, indirectCall: false,
      registerIndex: 0, delayImport: false, iatIndex: null }]);
  assert.deepEqual(warnings, []);
});

void test("parseControlTransfers rejects an out-of-bounds payload", () => {
  const warnings: string[] = [];

  assert.deepEqual(parseControlTransfers(block(2, 0), 0, 100, 5n, warnings), []);
  assert.ok(warnings.some(warning => /payload bounds/.test(warning)));
});
