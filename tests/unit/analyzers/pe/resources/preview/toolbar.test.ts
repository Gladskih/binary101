import { assertResourcePrefixWarnings } from "../../../../../helpers/resource-prefix-warnings.js";
import assert from "node:assert/strict";
import { test } from "node:test";
import { addToolbarPreview } from "../../../../../../analyzers/pe/resources/preview/toolbar.js";

const buildToolbar = (): Uint8Array => {
  // CToolBarData: version, image width, image height, item count, WORD command IDs.
  // https://github.com/adzm/atlmfc/blob/master/src/mfc/bartool.cpp
  const bytes = new Uint8Array(14);
  const view = new DataView(bytes.buffer);
  [1, 16, 15, 3, 100, 0, 101].forEach((value, index) => view.setUint16(index * 2, value, true));
  return bytes;
};

void test("reads toolbar dimensions and commands including zero-valued separators", () => {
  const result = addToolbarPreview(buildToolbar(), "TOOLBAR");
  assert.deepEqual(result?.preview?.toolbar, { version: 1, width: 16, height: 15, items: [100, 0, 101] });
  assert.equal(result?.issues, undefined);
  assert.equal(result?.preview?.previewKind, "toolbar");
});

void test("accepts an empty toolbar and reports exact malformed conditions", () => {
  const bytes = buildToolbar();
  const view = new DataView(bytes.buffer);
  assert.deepEqual(addToolbarPreview(bytes.subarray(0, 7), "TOOLBAR")?.issues,
    ["TOOLBAR header is truncated."]);
  assert.deepEqual(addToolbarPreview(bytes.subarray(0, 9), "TOOLBAR")?.issues,
    ["TOOLBAR command list is truncated."]);
  view.setUint16(6, 0, true);
  assert.equal(addToolbarPreview(bytes.subarray(0, 8), "TOOLBAR")?.issues, undefined);
  assert.deepEqual(addToolbarPreview(bytes.subarray(0, 8), "TOOLBAR")?.preview?.toolbar?.items, []);
  assert.deepEqual(addToolbarPreview(bytes, "TOOLBAR")?.issues, ["TOOLBAR contains trailing bytes."]);
  view.setUint16(2, 0, true);
  assert.deepEqual(addToolbarPreview(bytes.subarray(0, 8), "TOOLBAR")?.issues,
    ["TOOLBAR image dimensions are zero."]);
  view.setUint16(0, 2, true);
  assert.deepEqual(addToolbarPreview(bytes, "TOOLBAR")?.issues, ["TOOLBAR version 2 is unsupported."]);
});

void test("warns on truncated prefixes, unknown versions, zero dimensions and trailing bytes", () => {
  const bytes = buildToolbar();
  assertResourcePrefixWarnings(bytes, prefix => addToolbarPreview(prefix, "TOOLBAR"));
  new DataView(bytes.buffer).setUint16(0, 2, true);
  assert.ok(addToolbarPreview(bytes, "TOOLBAR")?.issues?.length);
  new DataView(bytes.buffer).setUint16(0, 1, true);
  bytes.fill(0, 2, 6);
  assert.match(addToolbarPreview(bytes, "TOOLBAR")?.issues?.[0] ?? "", /dimensions/);
  bytes.set([16, 0, 15, 0], 2);
  new DataView(bytes.buffer).setUint16(6, 2, true);
  assert.match(addToolbarPreview(bytes, "TOOLBAR")?.issues?.[0] ?? "", /trailing/);
  bytes[2] = 0;
  assert.match(addToolbarPreview(bytes, "TOOLBAR")?.issues?.[0] ?? "", /dimensions/);
  bytes[2] = 16;
  bytes[4] = 0;
  assert.match(addToolbarPreview(bytes, "TOOLBAR")?.issues?.[0] ?? "", /dimensions/);
  bytes.fill(0, 0, 6);
  assert.ok(addToolbarPreview(bytes, "TOOLBAR")?.issues?.length);
  assert.equal(addToolbarPreview(bytes, "other"), null);
});
