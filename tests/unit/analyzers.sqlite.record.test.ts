"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRecord } from "../../analyzers/sqlite/record.js";

const createRecordPayload = (): DataView => {
  const payloadSize = 15;
  const buffer = new ArrayBuffer(payloadSize);
  const view = new DataView(buffer);
  const serials = [0, 7, 8, 9, 13, 12];
  let cursor = 0;
  view.setUint8(cursor, 7); // header size
  cursor += 1;
  serials.forEach(serial => {
    view.setUint8(cursor, serial);
    cursor += 1;
  });
  view.setFloat64(7, 1.5, false);
  return view;
};

void test("parseRecord decodes diverse serial types", () => {
  const issues: string[] = [];
  const columnNames = ["null", "float", "c0", "c1", "text", "blob"];
  const view = createRecordPayload();
  const record = parseRecord(view, 0, view.byteLength, "UTF-8", issues, columnNames);
  assert.strictEqual(record.headerTruncated, false);
  assert.strictEqual(record.values[0]?.value, null);
  assert.strictEqual(record.values[1]?.value, 1.5);
  assert.strictEqual(record.values[2]?.value, 0);
  assert.strictEqual(record.values[3]?.value, 1);
  assert.strictEqual(record.values[4]?.value, "");
  assert.ok(record.values[5]?.value instanceof ArrayBuffer);
  assert.ok(issues.length === 0);
});

void test("parseRecord marks truncated headers when payload is short", () => {
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setUint8(0, 10); // header size greater than payload
  view.setUint8(1, 1); // one serial type
  const issues: string[] = [];
  const record = parseRecord(view, 0, view.byteLength, "UTF-8", issues, ["only"]);
  assert.strictEqual(record.headerTruncated, true);
  assert.strictEqual(record.values[0]?.truncated, true);
});
