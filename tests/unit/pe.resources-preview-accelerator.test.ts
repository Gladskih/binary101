"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addAcceleratorPreview } from "../../analyzers/pe/resources-preview-accelerator.js";
import { expectDefined } from "../helpers/expect-defined.js";

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
