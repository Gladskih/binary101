import assert from "node:assert/strict";
import { test } from "node:test";
import { readCrinklerModelParts } from "../../../../../analyzers/pe/packers/crinkler-models.js";
import { CRINKLER_30_PREFIX } from "../../../../fixtures/crinkler-bytes.js";

const fixtureModelView = (): DataView => {
  // The fixture's mov esi and bt operands locate the model records at [277, 294).
  const table = Uint8Array.from(Buffer.from(CRINKLER_30_PREFIX, "hex").subarray(277, 294));
  return new DataView(table.buffer);
};

void test("Crinkler 3 model records use even parity of the low byte on the last part", () => {
  const view = fixtureModelView();
  // The model pointer is relative to the supplied view; the values are unsigned positions.
  const parts = readCrinklerModelParts(view, 0, view.byteLength, 0x420000, "3.0");
  assert.deepEqual(parts?.map(part => [part.unpackedSize, part.models.length]), [[150, 4], [10, 1]]);
  assert.equal(parts?.[1]?.encodedWeights, 0xdfffffff);
});

void test("Crinkler model records reject a missing terminator or truncated final context mask", () => {
  const view = fixtureModelView();
  const end = view.byteLength;
  assert.equal(readCrinklerModelParts(view, 0, end - 1, 0x420000, "3.0"), null);
  // Toggle low-byte parity in the last record to make it announce another part.
  view.setUint8(12, 0xfe);
  assert.equal(readCrinklerModelParts(view, 0, end, 0x420000, "3.0"), null);
});

void test("Crinkler model records reject invalid ranges", () => {
  const view = fixtureModelView();
  assert.equal(readCrinklerModelParts(view, -1, view.byteLength, 0x420000, "3.0"), null);
  assert.equal(readCrinklerModelParts(view, 0, view.byteLength + 1, 0x420000, "3.0"), null);
  assert.equal(readCrinklerModelParts(view, 0, 0, 0x420000, "3.0"), null);
});
