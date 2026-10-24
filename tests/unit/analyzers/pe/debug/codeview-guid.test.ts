import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewGuid } from "../../../../../analyzers/pe/debug/codeview-guid.js";

void test("CodeView GUIDs retain Windows mixed byte order and the bounded view's byte offset", () => {
  const bytes = Uint8Array.from([255, 255, 0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 255]);
  assert.equal(readCodeViewGuid(new DataView(bytes.buffer, 1, 18), 1),
    "12345678-9abc-def0-1122-334455667788");
  assert.equal(readCodeViewGuid(new DataView(new Uint8Array(16).buffer), 0),
    "00000000-0000-0000-0000-000000000000");
});

for (const offset of [-1, 1, 0.5, Infinity, NaN]) {
  void test(`CodeView GUID offset ${offset} cannot read outside a 16-byte view`, () => {
    assert.throws(() => readCodeViewGuid(new DataView(new Uint8Array(32).buffer, 0, 16), offset), /bounds/);
  });
}

void test("CodeView a short GUID view cannot borrow bytes from the rest of its backing buffer", () => {
  assert.throws(() => readCodeViewGuid(new DataView(new Uint8Array(32).buffer, 0, 15), 0), /bounds/);
});
