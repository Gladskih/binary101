import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewFrame } from "../../../../../analyzers/pe/debug/codeview-frame-symbol.js";
import { frameRecord } from "../../../../fixtures/pe-codeview-locals.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView frame fields retain packed handler and flag positions", async () => {
  const warnings: string[] = [];
  const frame = await readCodeViewFrame(legacyReader(frameRecord(0x7fffff), warnings), 0x1012);

  assert.deepEqual(frame, { frame: { frameBytes: 64, paddingBytes: 8, paddingOffset: 24,
    savedRegisterBytes: 16, handler: { offset: 0x1234, section: 3 }, flags: 0x7fffff } });
  assert.deepEqual(warnings, []);
  assert.equal(await readCodeViewFrame(legacyReader([]), 0x1011), null);
});

void test("CodeView frame reserved bits are preserved and diagnosed", async () => {
  const warnings: string[] = [];
  const frame = await readCodeViewFrame(legacyReader(frameRecord(0xffffffff), warnings), 0x1012);

  assert.equal(frame?.frame.flags, 0xffffffff);
  assert.match(warnings.join(" | "), /reserved bits/);
});

for (const length of [0, 3, 4, 25, 29]) {
  void test(`CodeView frame checks the complete fixed body at size ${length}`, async () => {
    await assert.rejects(readCodeViewFrame(legacyReader(frameRecord().slice(0, length)), 0x1012), /bounds/);
  });
}
