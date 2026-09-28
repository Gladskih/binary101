import assert from "node:assert/strict";
import { test } from "node:test";
import { addDialogLayoutPreview } from "../../../../../../analyzers/pe/resources/preview/dialog-layout.js";

const layout = (values: number[]): Uint8Array => {
  const bytes = new Uint8Array(values.length * 2);
  const view = new DataView(bytes.buffer);
  values.forEach((value, index) => view.setUint16(index * 2, value, true));
  return bytes;
};

void test("reads signed MFC layout ratios and clamps them to 0–100", () => {
  // MFC CMFCDynamicLayoutData::ReadResource: v0, then four signed WORDs per child.
  // https://github.com/adzm/atlmfc/blob/master/src/mfc/afxlayout.cpp
  const result = addDialogLayoutPreview(layout([0, 10, 20, 30, 40, 0xffff, 101, 50, 0]),
    "AFX_DIALOG_LAYOUT");
  assert.deepEqual(result?.preview?.dialogLayout, { version: 0, controls: [
    { moveX: 10, moveY: 20, sizeX: 30, sizeY: 40 },
    { moveX: 0, moveY: 100, sizeX: 50, sizeY: 0 }
  ] });
  assert.equal(result?.issues, undefined);
});

void test("reports missing header, unknown version and partial records", () => {
  assert.equal(addDialogLayoutPreview(new Uint8Array(0), "AFX_DIALOG_LAYOUT")?.issues?.length, 1);
  assert.equal(addDialogLayoutPreview(layout([1]), "AFX_DIALOG_LAYOUT")?.issues?.length, 1);
  assert.equal(addDialogLayoutPreview(layout([0, 1, 2]), "AFX_DIALOG_LAYOUT")?.issues?.length, 1);
  assert.deepEqual(addDialogLayoutPreview(layout([0]), "AFX_DIALOG_LAYOUT")?.preview?.dialogLayout,
    { version: 0, controls: [] });
  assert.equal(addDialogLayoutPreview(layout([0]), "DIALOG"), null);
});
