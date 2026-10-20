import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createPeDebugFile } from "../../../../fixtures/pe-debug-file.js";

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

void test("full PE parsing retains named linker regions beyond a presentation page", async () => {
  const parsed = await parsePe(createPeDebugFile(101));

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.debug?.warning, undefined);
  assert.equal(parsed.debug?.entries?.[3]?.pogo?.entries.length, 101);
  assert.equal(parsed.debug?.entries?.[3]?.pogo?.entries[99]?.name, ".text$region_99");
  assert.equal(parsed.debug?.entries?.[3]?.pogo?.entries[100]?.name, ".text$largest");
});
