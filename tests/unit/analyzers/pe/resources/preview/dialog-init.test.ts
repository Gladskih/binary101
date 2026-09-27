import { assertResourcePrefixWarnings } from "../../../../../helpers/resource-prefix-warnings.js";
import assert from "node:assert/strict";
import { test } from "node:test";
import { addDialogInitPreview } from "../../../../../../analyzers/pe/resources/preview/dialog-init.js";

const buildInit = (): Uint8Array => {
  const bytes = new Uint8Array(13);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 100, true);
  view.setUint16(2, 0x403, true); // Win16 CB_ADDSTRING used by MFC DLGINIT.
  view.setUint32(4, 3, true);
  bytes.set([65, 66, 0], 8);
  return bytes;
};

void test("reads unaligned DLGINIT records and their counted payloads", () => {
  const result = addDialogInitPreview(buildInit(), "DLGINIT");
  assert.deepEqual(result?.preview?.dialogInit, { entries: [
    { controlId: 100, message: 0x403, data: new Uint8Array([65, 66, 0]) }
  ] });
  assert.equal(result?.issues, undefined);
  assert.equal(result?.preview?.previewKind, "dialogInit");
});

void test("distinguishes exact payload boundaries, unknown messages and empty ADDSTRING", () => {
  const bytes = buildInit();
  const view = new DataView(bytes.buffer);
  assert.deepEqual(addDialogInitPreview(bytes.subarray(0, 6), "DLGINIT")?.issues,
    ["DLGINIT record header is truncated."]);
  assert.deepEqual(addDialogInitPreview(bytes.subarray(0, 9), "DLGINIT")?.issues,
    ["DLGINIT record payload is truncated."]);
  assert.deepEqual(addDialogInitPreview(bytes.subarray(0, 11), "DLGINIT")?.issues,
    ["DLGINIT list lacks its terminating zero control ID."]);
  view.setUint32(4, 0, true);
  view.setUint16(2, 0xffff, true);
  assert.deepEqual(addDialogInitPreview(bytes.subarray(0, 8), "DLGINIT")?.issues,
    ["DLGINIT list lacks its terminating zero control ID."]);
  bytes.fill(0, 8, 10);
  assert.equal(addDialogInitPreview(bytes.subarray(0, 10), "DLGINIT")?.issues, undefined);
  view.setUint16(2, 0x401, true);
  assert.deepEqual(addDialogInitPreview(bytes.subarray(0, 10), "DLGINIT")?.issues,
    ["DLGINIT ADDSTRING payload lacks a terminating NUL."]);
});

void test("warns for every truncated prefix, extreme sizes and missing string terminators", () => {
  const bytes = buildInit();
  assertResourcePrefixWarnings(bytes, prefix => addDialogInitPreview(prefix, "DLGINIT"));
  bytes[10] = 65;
  assert.ok(addDialogInitPreview(bytes, "DLGINIT")?.issues?.length);
  new DataView(bytes.buffer).setUint32(4, 0xffffffff, true);
  assert.ok(addDialogInitPreview(bytes, "DLGINIT")?.issues?.length);
  assert.equal(addDialogInitPreview(bytes, "other"), null);
  assert.equal(addDialogInitPreview(new Uint8Array(2), "DLGINIT")?.issues, undefined);
});
