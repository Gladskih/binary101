import assert from "node:assert/strict";
import { test } from "node:test";
import { HllTypeFields } from "../../../../../analyzers/pe/debug/hll-type-fields.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";

for (const [bytes, value] of [[[133, 0, 128], 32768], [[134, 0, 0, 0, 128], 2147483648],
  [[136, 255], -1], [[137, 255, 255], -1], [[138, 255, 255, 255, 255], -1], [[139, 255], 255],
  [[136, 1], 1], [[137, 1, 0], 1], [[138, 1, 0, 0, 0], 1]] as const) {
  void test(`HLL numeric fields ${bytes} retain their own signedness`, async () => {
    const fields = new HllTypeFields(legacyReader(bytes));
    assert.equal(await fields.span(), value);
    assert.equal(fields.offset, bytes.length);
  });
}

void test("HLL field IDs and truncated strings fail within the record", async () => {
  await assert.rejects(new HllTypeFields(legacyReader([128])).index(), /index field/);
  await assert.rejects(new HllTypeFields(legacyReader([128])).string(), /string field/);
  await assert.rejects(new HllTypeFields(legacyReader([128])).span(), /numeric field/);
  await assert.rejects(new HllTypeFields(legacyReader([130, 2, 65])).string(), /bounds/);
  await assert.rejects(new HllTypeFields(legacyReader([133, 0])).span(), /bounds/);
});
