"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../../../../../../analyzers/pe/directories/exports.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../../analyzers/pe/index.js";
import { createPagedPeExportsFile } from "../../../../../fixtures/pe-export-table-file.js";

const encoder = new TextEncoder();

const mapHeaderAcrossEof = (rva: number, fileSize: number): number => {
  if (rva >= 128 && rva < 148) return fileSize - 20 + rva - 128;
  if (rva >= 148 && rva < 168) return 200 + rva - 148;
  return rva;
};

void test("PE parsing preserves export aliases through the real header RVA mapper", async () => {
  const result = await parsePe(new File([createPagedPeExportsFile()], "exports.exe"));

  assert.ok(result && isPeWindowsParseResult(result));
  assert.equal(result.exports?.entries.length, 251);
  assert.deepEqual(result.exports?.entries[250]?.names, ["Alpha<", "Beta&lt;"]);
  assert.deepEqual(result.exports?.issues, []);
});
const parseExportFixture = (
  bytes: Uint8Array,
  directory: { rva: number; size: number },
  mapping: (rva: number) => number | null = rva => rva
) => parseExportDirectory(new MockFile(bytes), [{ name: "EXPORT", ...directory }], mapping);

// Field offsets: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table
const createExportRegressionFixture = (count = 1) => {
  const bytes = new Uint8Array(Math.max(1024, 400 + count * 4));
  const view = new DataView(bytes.buffer);
  view.setUint32(128 + 16, 1, true);
  view.setUint32(128 + 20, count, true);
  view.setUint32(128 + 28, 400, true);
  view.setUint32(400, 0x7000, true);
  return { bytes, view };
};

for (const missingRva of [421, 431]) {
  void test(`exports reject a name/ordinal entry with an unmapped byte at ${missingRva}`, async () => {
    const { bytes, view } = createExportRegressionFixture();
    view.setUint32(128 + 24, 1, true);
    view.setUint32(128 + 32, 420, true);
    view.setUint32(128 + 36, 430, true);
    view.setUint32(420, 440, true);
    bytes.set(encoder.encode("Alpha\0"), 440);

    const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
      rva => rva === missingRva ? null : rva);

    assert.deepEqual(result?.entries[0]?.names, []);
    assert.match(result?.issues.join(" ") ?? "", /name\/ordinal tables.*truncated/i);
  });
}

void test("exports assemble a split ordinal index without reading its raw-file neighbor", async () => {
  const { bytes, view } = createExportRegressionFixture();
  view.setUint32(128 + 24, 1, true);
  view.setUint32(128 + 32, 420, true);
  view.setUint32(128 + 36, 430, true);
  view.setUint32(420, 440, true);
  bytes[431] = 1; // Would create out-of-range index 256 if read contiguously.
  bytes.set(encoder.encode("Alpha\0"), 440);

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
    rva => rva === 431 ? 600 : rva);

  assert.deepEqual(result?.entries[0]?.names, ["Alpha"]);
  assert.deepEqual(result?.issues, []);
});

void test("exports preserve all names associated with the same EAT index", async () => {
  const { bytes, view } = createExportRegressionFixture();
  view.setUint32(128 + 24, 2, true);
  view.setUint32(128 + 32, 420, true);
  view.setUint32(128 + 36, 430, true);
  view.setUint32(420, 440, true);
  view.setUint32(424, 460, true);
  bytes.set(encoder.encode("Alpha\0"), 440);
  bytes.set(encoder.encode("Beta\0"), 460);

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 });

  assert.deepEqual(result?.entries[0]?.names, ["Alpha", "Beta"]);
  assert.deepEqual(result?.issues, []);
});

void test("exports stop at an unmapped byte inside an EAT entry", async () => {
  const { bytes } = createExportRegressionFixture();

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
    rva => rva === 401 ? null : rva);

  assert.deepEqual(result?.entries, []);
  assert.match(result?.issues.join(" ") ?? "", /address table.*truncated/i);
});

void test("exports assemble an EAT entry across discontiguous file ranges", async () => {
  const { bytes, view } = createExportRegressionFixture();
  view.setUint16(400, 0x1234, true);
  view.setUint16(600, 0x5678, true);

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
    rva => rva >= 402 && rva < 404 ? rva + 198 : rva);

  assert.equal(result?.entries[0]?.rva, 0x56781234);
  assert.deepEqual(result?.issues, []);
});

void test("exports do not wrap EAT addresses beyond the 32-bit RVA space", async () => {
  const { bytes, view } = createExportRegressionFixture(2);
  view.setUint32(128 + 28, 0xfffffffc, true); // Last complete DWORD in the RVA space.

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
    rva => rva >= 0xfffffffc ? rva - 0xfffffffc + 400 : rva);

  assert.equal(result?.entries.length, 1);
  assert.match(result?.issues.join(" ") ?? "", /address table.*truncated/i);
});

void test("exports warn about a header with an unmapped final byte", async () => {
  const { bytes } = createExportRegressionFixture();

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
    rva => rva === 167 ? null : rva);

  assert.deepEqual(result?.entries, []);
  assert.match(result?.issues.join(" ") ?? "", /header.*truncated/i);
});

void test("exports assemble a header whose first raw span ends at EOF", async () => {
  const { bytes } = createExportRegressionFixture();
  const header = bytes.slice(128, 168);
  bytes.set(header.subarray(0, 20), bytes.length - 20);
  bytes.set(header.subarray(20), 200);

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 },
    rva => mapHeaderAcrossEof(rva, bytes.length));

  assert.equal(result?.entries[0]?.rva, 0x7000);
  assert.deepEqual(result?.issues, []);
});

void test("exports retain large EATs without exceeding the argument limit", async () => {
  const count = 200000; // Exceeds the engine's call argument limit; still under 1 MiB of data.
  const { bytes } = createExportRegressionFixture(count);

  const result = await parseExportFixture(bytes, { rva: 128, size: 40 });

  assert.equal(result?.entries.length, count);
  assert.deepEqual(result?.issues, []);
});
