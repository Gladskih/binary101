import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createPeDebugFile, createPeWithDebugPayloads } from "../../../../fixtures/pe-debug-file.js";
import { createLegacyCodeView } from "../../../../fixtures/pe-legacy-codeview.js";

void test("full PE parsing recognizes inline CodeView without an external PDB path", async () => {
  const parsed = await parsePe(createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView() }]));

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.debug?.warning, undefined);
  assert.equal(parsed.debug?.entries?.[0]?.legacyCodeView?.signature, "NB09");
  assert.equal(parsed.debug?.entries?.[0]?.codeView, undefined);
  assert.equal(parsed.debug?.entries?.[0]?.rawPayload, undefined);
});

void test("full PE parsing retains embedded PDB, frame metadata, linker names and chained DBG paths", async () => {
  const parsed = await parsePe(createPeDebugFile());

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.debug?.warning, undefined);
  assert.equal(parsed.debug?.entries?.length, 5);
  assert.equal(parsed.debug?.entries?.[0]?.embeddedPortablePdb?.portablePdb?.documents[0]?.name, "source.cs");
  assert.deepEqual(parsed.debug?.entries?.[0]?.embeddedPortablePdb?.portablePdb?.sequencePoints,
    { visible: 1, hidden: 1 });
  assert.equal(parsed.debug?.entries?.[1]?.fpo?.records.length, 26);
  assert.equal(parsed.debug?.entries?.[2]?.omap?.records.length, 3);
  assert.deepEqual(parsed.debug?.entries?.[3]?.pogo?.entries.map(region => region.name),
    [".text$first", ".text$largest"]);
  assert.deepEqual(parsed.debug?.entries?.[4]?.misc?.records.map(record => record.text),
    ["first.dbg", "second.dbg"]);
});

void test("full PE parsing recognizes FIXUP metadata instead of opaque fallback", async () => {
  const parsed = await parsePe(createPeWithDebugPayloads([{ type: 6, data: Uint8Array.of(
    4, 0, 0, 128, 0, 16, 0, 0, 4, 16, 0, 0) }]));

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.debug?.warning, undefined);
  assert.deepEqual(parsed.debug?.entries?.[0]?.fixup?.records,
    [{ type: 4, extra: 0x8000, rva: 0x1000, targetRva: 0x1004 }]);
  assert.equal(parsed.debug?.entries?.[0]?.rawPayload, undefined);
});

void test("full PE parsing retains named linker regions beyond a presentation page", async () => {
  const parsed = await parsePe(createPeDebugFile(101));

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.debug?.warning, undefined);
  assert.equal(parsed.debug?.entries?.[3]?.pogo?.entries.length, 101);
  assert.equal(parsed.debug?.entries?.[3]?.pogo?.entries[99]?.name, ".text$region_99");
  assert.equal(parsed.debug?.entries?.[3]?.pogo?.entries[100]?.name, ".text$largest");
});
