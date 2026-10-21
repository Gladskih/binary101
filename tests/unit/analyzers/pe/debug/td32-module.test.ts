import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32Module } from "../../../../../analyzers/pe/debug/td32-module.js";
import { td32Module } from "../../../../fixtures/pe-td32.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("TD32 module header and contribution fields retain their independent values", async () => {
  const warnings: string[] = [];
  const bytes = td32Module();
  bytes[0] = 1;
  bytes[2] = 2;

  const parsed = await readTd32Module(legacyReader(bytes, warnings));

  assert.deepEqual(parsed, { kind: "module", overlay: 1, library: 2, style: 0x4454,
    nameIndex: 1, timestamp: 123, segments: [{ segment: 1, flags: 1, offset: 16, size: 32 }] });
  assert.deepEqual(warnings, []);
});

void test("TD32 module contributions keep both code and data segment values", async () => {
  const bytes = Uint8Array.from([...td32Module(), ...legacyU16(2), ...legacyU16(0), ...legacyU32(48), ...legacyU32(8)]);
  bytes[4] = 2;
  const warnings: string[] = [];

  const parsed = await readTd32Module(legacyReader(bytes, warnings));

  assert.deepEqual(parsed.segments, [{ segment: 1, flags: 1, offset: 16, size: 32 },
    { segment: 2, flags: 0, offset: 48, size: 8 }]);
  assert.deepEqual(warnings, []);
  bytes[4] = 0;
  assert.deepEqual((await readTd32Module(legacyReader(bytes.subarray(0, 28), warnings))).segments, []);
  assert.deepEqual(warnings, []);
});

void test("TD32 module rejects short headers and arrays and warns on unknown attributes", async () => {
  const bytes = td32Module();
  const warnings: string[] = [];
  bytes[16] = 1;
  bytes[30] = 2;

  await readTd32Module(legacyReader(bytes, warnings));

  assert.match(warnings.join(" | "), /reserved fields/);
  assert.match(warnings.join(" | "), /unknown attributes/);
  await assert.rejects(readTd32Module(legacyReader(bytes.subarray(0, 27))), /bounds/);
  await assert.rejects(readTd32Module(legacyReader(bytes.subarray(0, 39))), /segments are truncated/);
});
