"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseChpeRuntimeFunctions } from "../../../../../analyzers/pe/load-config/chpe-runtime-functions.js";
import { createPeRvaMapping } from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const TABLE_RVA = 0x40;

const parseTable = async (bytes: Uint8Array, rva = TABLE_RVA, size = 8) => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const entries = await parseChpeRuntimeFunctions(
    new MockFile(bytes, "chpe-runtime-functions.bin"),
    createPeRvaMapping(bytes.length, [], bytes.length, value => value),
    warnings,
    notes,
    rva,
    size
  );
  return { entries, warnings, notes };
};

const writeRuntimeFunctionFixture = (view: DataView, unwindWords: number[]): void => {
  unwindWords.forEach((unwindWord, index) => {
    view.setUint32(TABLE_RVA + index * 8, 0x1000 + index * 0x20, true);
    view.setUint32(TABLE_RVA + index * 8 + 4, unwindWord, true);
  });
};

void test("parseChpeRuntimeFunctions decodes every ARM64 pdata form", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  // Microsoft ARM64 .pdata: flag bits 0..1, packed fields above them, 8 bytes per entry.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170
  const unwindWords = [
    0x00000200,
    0x02934011,
    0x00200001,
    0x00400002,
    0x00600001,
    0x0000048f
  ];
  writeRuntimeFunctionFixture(view, unwindWords);

  const { entries, warnings } = await parseTable(bytes, TABLE_RVA, unwindWords.length * 8);

  assert.deepEqual(entries[0], {
    beginRva: 0x1000, unwindKind: "exception", exceptionInformationRva: 0x200
  });
  assert.deepEqual(entries[1], {
    beginRva: 0x1020,
    unwindKind: "packed",
    functionLengthBytes: 16,
    savedFpRegisterField: 2,
    savedIntegerRegisterCount: 3,
    homesIntegerParameters: true,
    chainReturn: "unchained",
    frameSizeBytes: 80
  });
  assert.deepEqual(entries.slice(2, 5).map(entry => (
    "chainReturn" in entry ? [entry.unwindKind, entry.chainReturn] : []
  )), [
    ["packed", "saves-lr"],
    ["packed-fragment", "chained-pac"],
    ["packed", "chained"]
  ]);
  assert.equal(entries[2]?.unwindKind === "packed" && entries[2].homesIntegerParameters, false);
  assert.deepEqual(entries[5], {
    beginRva: 0x10a0, unwindKind: "chained", targetPdataRva: 0x48c
  });
  assert.deepEqual(warnings, []);
});

// RVAs are DWORDs: 0x80000000 sets the sign bit, and 0xfffffffc is the largest
// DWORD-aligned RVA. The two low bits of each input retain the chained-record tag.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://tc39.es/ecma262/multipage/ecmascript-data-types-and-values.html#sec-numberbitwiseop
for (const [unwindWord, targetPdataRva] of [
  [0x80000003, 0x80000000],
  [0xffffffff, 0xfffffffc]
] as const) {
  void test(`parseChpeRuntimeFunctions preserves unsigned chained RVA 0x${targetPdataRva.toString(16)}`, async () => {
    const bytes = new Uint8Array(TABLE_RVA + 8); // One 8-byte ARM64 .pdata record.
    writeRuntimeFunctionFixture(new DataView(bytes.buffer), [unwindWord]);

    const { entries, warnings, notes } = await parseTable(bytes);

    assert.deepEqual(entries, [{ beginRva: 0x1000, unwindKind: "chained", targetPdataRva }]);
    assert.deepEqual(warnings, []);
    assert.deepEqual(notes, []);
  });
}

void test("parseChpeRuntimeFunctions handles empty, misaligned, missing, and truncated tables", async () => {
  const bytes = new Uint8Array(0x50).fill(0);
  const empty = await parseTable(bytes, 0, 0);
  const misaligned = await parseTable(bytes, TABLE_RVA, 9);
  const missing = await parseTable(bytes, 0, 8);
  const truncated = await parseTable(bytes, TABLE_RVA, 24);

  assert.deepEqual(empty.entries, []);
  assert.ok(misaligned.warnings.some(warning => warning.includes("not divisible by 8")));
  assert.ok(missing.warnings.some(warning => warning.includes(
    "CHPE ExtraRFETable has entries but no valid table RVA"
  )));
  assert.ok(truncated.warnings.some(warning => warning.includes("is truncated")));
});
