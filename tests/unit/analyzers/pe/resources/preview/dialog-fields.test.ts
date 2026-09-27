import assert from "node:assert/strict";
import { test } from "node:test";
import { readDialogField, readDialogFont } from "../../../../../../analyzers/pe/resources/preview/dialog-fields.js";

void test("handles ordinals only as classes when reading a class field", () => {
  const view = new DataView(new Uint8Array([255, 255, 128, 0]).buffer);
  assert.equal(readDialogField(view, 0, "class", []).value, "BUTTON");
  assert.equal(readDialogField(view, 0, "menu", []).value, "#128");
  assert.equal(readDialogField(view, 0, "title", []).value, "#128");
  const unknown = new DataView(new Uint8Array([255, 255, 1, 0]).buffer);
  assert.equal(readDialogField(unknown, 0, "class", []).value, "#1");
});

void test("warns on missing fields, incomplete ordinals, unterminated strings and font metadata", () => {
  const issues: string[] = [];
  readDialogField(new DataView(new ArrayBuffer(0)), 0, "menu", issues);
  readDialogField(new DataView(new Uint8Array([255, 255]).buffer), 0, "class", issues);
  readDialogField(new DataView(new Uint8Array([65, 0, 66]).buffer), 0, "title", issues);
  readDialogFont(new DataView(new ArrayBuffer(0)), 0, 0x40, "standard", issues);
  readDialogFont(new DataView(new ArrayBuffer(4)), 0, 0x40, "extended", issues);

  assert.equal(issues.length, 5);
  assert.equal(readDialogFont(new DataView(new ArrayBuffer(0)), 0, 0, "standard", []).font, null);
});

void test("reads extended italic fonts and empty dialog fields", () => {
  const view = new DataView(new Uint8Array([9, 0, 144, 1, 1, 2, 65, 0, 0, 0]).buffer);
  assert.deepEqual(readDialogFont(view, 0, 0x40, "extended", []), {
    font: { pointSize: 9, weight: 400, italic: true, charset: 2, typeface: "A" }, nextOffset: 10
  });
  assert.deepEqual(readDialogField(view, 8, "title", []), { value: null, nextOffset: 10 });
});
