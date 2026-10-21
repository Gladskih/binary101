import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewPublics, readLegacyCodeViewOldLines,
  readLegacyCodeViewFrameMap } from "../../../../../analyzers/pe/debug/legacy-codeview-compatibility.js";
import { legacyReader, legacyPascal, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("old PE CodeView publics retain counted names and advance by complete 32-bit entries", async () => {
  const bytes = [...legacyU32(16), ...legacyU16(2), ...legacyU16(0), ...legacyPascal("public"),
    ...legacyU32(24), ...legacyU16(2), ...legacyU16(0), ...legacyPascal("other")];

  assert.deepEqual(await readLegacyCodeViewPublics(legacyReader(bytes)), { kind: "publics", names: ["public", "other"] });
  assert.deepEqual(await readLegacyCodeViewPublics(legacyReader([])), { kind: "publics", names: [] });
  await assert.rejects(readLegacyCodeViewPublics(legacyReader(bytes.slice(0, -1))), /bounds/);
});

void test("old PE CodeView source lines interleave 16-bit lines and 32-bit offsets", async () => {
  const bytes = [...legacyPascal("source.c"), ...legacyU16(2), ...legacyU16(2),
    ...legacyU16(7), ...legacyU32(16), ...legacyU16(9), ...legacyU32(24)];

  assert.deepEqual(await readLegacyCodeViewOldLines(legacyReader(bytes)), { kind: "oldLines", files: [
    { name: "source.c", segment: 2, lines: [{ line: 7, offset: 16 }, { line: 9, offset: 24 }] }] });
  assert.deepEqual(await readLegacyCodeViewOldLines(legacyReader([])), { kind: "oldLines", files: [] });
  await assert.rejects(readLegacyCodeViewOldLines(legacyReader(bytes.slice(0, -1))), /line pairs/);
});

void test("CodeView MPC validates its complete segment-to-frame array", async () => {
  assert.deepEqual(await readLegacyCodeViewFrameMap(legacyReader([2, 0, 0, 0, 8, 0])), { kind: "frameMap", frames: [0, 8] });
  assert.deepEqual(await readLegacyCodeViewFrameMap(legacyReader([0, 0])), { kind: "frameMap", frames: [] });
  await assert.rejects(readLegacyCodeViewFrameMap(legacyReader([2, 0, 8, 0])), /map is truncated/);
});
