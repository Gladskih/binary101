"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addAcceleratorPreview } from "../../../../../../analyzers/pe/resources/preview/accelerator.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

// fVirt flags for ACCELTABLEENTRY come from the accelerator-table resource format. Source:
// https://learn.microsoft.com/en-us/windows/win32/menurc/accelerators-resource
const buildAcceleratorTable = (): Uint8Array => {
  const bytes = new Uint8Array(16).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, 0x01 | 0x08); // FVIRTKEY | FCONTROL
  view.setUint16(2, "O".charCodeAt(0), true);
  view.setUint16(4, 100, true);
  view.setUint8(8, 0x01 | 0x04 | 0x80); // FVIRTKEY | FSHIFT | FLAST
  view.setUint16(10, 0x70, true); // VK_F1. Source: https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
  view.setUint16(12, 200, true);
  return bytes;
};

void test("addAcceleratorPreview renders shortcut entries from ACCELERATOR resources", () => {
  const result = addAcceleratorPreview(buildAcceleratorTable(), "ACCELERATOR");

  assert.strictEqual(result?.preview?.previewKind, "accelerator");
  assert.deepEqual(expectDefined(result?.preview?.acceleratorPreview).entries[0], {
    id: 100,
    key: "O",
    modifiers: ["Ctrl"],
    flags: ["Ctrl", "VirtualKey"]
  });
  assert.deepEqual(expectDefined(result?.preview?.acceleratorPreview).entries[1], {
    id: 200,
    key: "F1",
    modifiers: ["Shift"],
    flags: ["Shift", "VirtualKey"]
  });
});

void test("keeps eight-byte stride when a final record loses its padding", () => {
  const result = addAcceleratorPreview(buildAcceleratorTable().subarray(0, 14), "ACCELERATOR");
  assert.equal(result?.preview?.acceleratorPreview?.entries[1]?.id, 200);
  assert.ok(result?.issues?.length);
});

void test("decodes navigation virtual keys", () => {
  const bytes = buildAcceleratorTable();
  new DataView(bytes.buffer).setUint16(2, 0x21, true); // VK_PRIOR (Page Up).
  assert.equal(addAcceleratorPreview(bytes, "ACCELERATOR")?.preview?.acceleratorPreview?.entries[0]?.key,
    "VK_PRIOR");
});

void test("handles empty, incomplete and unterminated tables and WORD-sized flags", () => {
  const bytes = buildAcceleratorTable();
  const view = new DataView(bytes.buffer);
  view.setUint16(8, 0x100, true); // Unknown flag in the high byte; final marker absent.
  assert.equal(addAcceleratorPreview(bytes, "other"), null);
  assert.ok(addAcceleratorPreview(new Uint8Array(), "ACCELERATOR")?.issues?.length);
  assert.ok(addAcceleratorPreview(bytes.subarray(0, 5), "ACCELERATOR")?.issues?.length);
  assert.equal(addAcceleratorPreview(bytes, "ACCELERATOR")?.issues?.length, 2);
  view.setUint16(0, 0x92, true); // ASCII, FNOINVERT, FALT, FLAST.
  view.setUint16(2, 65, true);
  assert.equal(addAcceleratorPreview(bytes, "ACCELERATOR")?.preview?.acceleratorPreview?.entries[0]?.key, "A");
});
