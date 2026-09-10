import assert from "node:assert/strict";
import { test } from "node:test";
import { ElfCoreNoteReader } from "../../../../analyzers/elf/core-note-reader.js";

void test("reads both byte orders, signed values and bounded strings", () => {
  const reader = new ElfCoreNoteReader(new Uint8Array([0xff, 0xfe, 65, 0, 66]), 4, "big");
  assert.equal(reader.unsigned(0, 2), 65534n);
  assert.equal(reader.signed(0, 2), -2n);
  assert.equal(reader.text(2, 3), "A");
  assert.equal(new ElfCoreNoteReader(reader.bytes, 4, "little").unsigned(0, 2), 65279n);
  assert.deepEqual(reader.fields(["value"], 0, 2), [{ name: "value", value: 65534n }]);
  assert.deepEqual(reader.issues, []);
});

void test("omits out-of-bounds fields and emits one truncation warning", () => {
  const reader = new ElfCoreNoteReader(new Uint8Array(2), 8, "little");
  assert.equal(reader.contains(-1, 1), false);
  assert.equal(reader.contains(0, -1), false);
  assert.equal(reader.unsigned(0), 0n);
  assert.equal(reader.text(1, 2), "");
  assert.deepEqual(reader.fields(["missing"], 1, 2), []);
  assert.deepEqual(reader.issues, ["Core note descriptor is truncated."]);
});
