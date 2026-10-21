import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewDirectories } from "../../../../../analyzers/pe/debug/legacy-codeview-directory.js";
import { createLegacyCodeView, legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("legacy directory respects declared header and entry sizes, including extensions", async () => {
  const bytes = createLegacyCodeView();
  const directories = await readLegacyCodeViewDirectories(legacyReader(bytes), 8);

  assert.equal(directories.length, 1);
  assert.equal(directories[0]?.entries.length, 4);
  assert.deepEqual(directories[0]?.entries[0], { type: 0x120, module: 1, offset: 72, size: 31 });
});

void test("legacy directory chain is finite and retains complete entries before truncation", async () => {
  const bytes = createLegacyCodeView();
  bytes.set(legacyU32(8), 16);
  const warnings: string[] = [];
  const directories = await readLegacyCodeViewDirectories(legacyReader(bytes, warnings), 8);

  assert.equal(directories.length, 1);
  assert.equal(directories[0]?.entries.length, 4);
  assert.match(warnings.join(" | "), /cycle/);
});

for (const [offset, values, pattern] of [
  [8, [15, 0], /header or entry/], [10, [11, 0], /header or entry/],
  [12, [255, 255, 255, 255], /past payload bounds/], [8, [255, 255], /bounds/]
] as const) void test(`legacy directory warns for malformed header at ${offset}: ${values}`, async () => {
  const bytes = createLegacyCodeView([]);
  bytes.set(values, offset);
  const warnings: string[] = [];
  await readLegacyCodeViewDirectories(legacyReader(bytes, warnings), 8);

  assert.match(warnings.join(" | "), pattern);
});

void test("legacy directory reports missing or out-of-range first directories", async () => {
  const warnings: string[] = [];
  const reader = legacyReader([], warnings);

  assert.deepEqual(await readLegacyCodeViewDirectories(reader, 0), []);
  assert.deepEqual(await readLegacyCodeViewDirectories(reader, 1), []);
  assert.match(warnings.join(" | "), /offset is zero/);
  assert.match(warnings.join(" | "), /bounds/);
});

void test("legacy directory preserves complete entries and flags without reading past a physical boundary", async () => {
  const bytes = createLegacyCodeView([{ type: 0x999, module: 1, data: new Uint8Array() },
    { type: 0x999, module: 2, data: new Uint8Array() }]);
  bytes.set(legacyU32(0x01020304), 20);
  const completeWarnings: string[] = [];
  const complete = await readLegacyCodeViewDirectories(legacyReader(bytes, completeWarnings), 8);
  bytes.set(legacyU32(3), 12);
  const partialWarnings: string[] = [];
  const partial = await readLegacyCodeViewDirectories(legacyReader(bytes, partialWarnings), 8);

  assert.equal(complete[0]?.flags, 0x01020304);
  assert.deepEqual(completeWarnings, []);
  assert.equal(partial[0]?.entries.length, 2);
  assert.deepEqual(partialWarnings, ["CodeView directory entries extend past payload bounds."]);
});

void test("legacy directory rejects overlapping generations while allowing physically reordered chains", async () => {
  const bytes = new Uint8Array(64);
  bytes.set([16, 0, 12, 0, ...legacyU32(2), ...legacyU32(40), 0, 0, 0, 0], 8);
  bytes.set([16, 0, 12, 0, ...legacyU32(0), ...legacyU32(0), 0, 0, 0, 0], 40);
  const warnings: string[] = [];
  const overlapping = await readLegacyCodeViewDirectories(legacyReader(bytes, warnings), 8);
  bytes.set(legacyU32(0), 12);
  bytes.set(legacyU32(8), 48);
  bytes.set(legacyU32(0), 16);
  const reorderedWarnings: string[] = [];
  const reordered = await readLegacyCodeViewDirectories(legacyReader(bytes, reorderedWarnings), 40);

  assert.equal(overlapping.length, 1);
  assert.deepEqual(warnings, ["Error: CodeView directory ranges overlap."]);
  assert.equal(reordered.length, 2);
  assert.deepEqual(reorderedWarnings, []);
  bytes.set(legacyU32(40), 16);
  bytes.set(legacyU32(0), 48);
  const orderedWarnings: string[] = [];
  assert.equal((await readLegacyCodeViewDirectories(legacyReader(bytes, orderedWarnings), 8)).length, 2);
  assert.deepEqual(orderedWarnings, []);
});

void test("legacy directory allows adjacent generations in either physical order", async () => {
  const bytes = new Uint8Array(40);
  bytes.set([16, 0, 12, 0, ...legacyU32(0), ...legacyU32(24), 0, 0, 0, 0], 8);
  bytes.set([16, 0, 12, 0, ...legacyU32(0), ...legacyU32(0), 0, 0, 0, 0], 24);
  const forwardWarnings: string[] = [];
  const forward = await readLegacyCodeViewDirectories(legacyReader(bytes, forwardWarnings), 8);
  bytes.set(legacyU32(0), 16);
  bytes.set(legacyU32(8), 32);
  const backwardWarnings: string[] = [];
  const backward = await readLegacyCodeViewDirectories(legacyReader(bytes, backwardWarnings), 24);

  assert.equal(forward.length, 2);
  assert.equal(backward.length, 2);
  assert.deepEqual(forwardWarnings, []);
  assert.deepEqual(backwardWarnings, []);
});

void test("legacy directory rejects a later generation that wraps around an earlier physical range", async () => {
  const bytes = new Uint8Array(64);
  bytes.set([16, 0, 12, 0, ...legacyU32(3), ...legacyU32(0), 0, 0, 0, 0], 8);
  bytes.set([16, 0, 12, 0, ...legacyU32(0), ...legacyU32(8), 0, 0, 0, 0], 40);
  const warnings: string[] = [];
  const directories = await readLegacyCodeViewDirectories(legacyReader(bytes, warnings), 40);

  assert.equal(directories.length, 1);
  assert.deepEqual(warnings, ["Error: CodeView directory ranges overlap."]);
});
