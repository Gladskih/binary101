import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfUnwindLocation, readElfUnwindPointer } from "../../../../analyzers/elf/unwind-pointer.js";
import { unwindCursor } from "../../../fixtures/elf-unwind.js";

for (const [encoding, bytes, expected] of [
  [0, [1, 0, 0, 0], 1n], [1, [129, 1], 129n], [2, [2, 0], 2n],
  [3, [3, 0, 0, 0], 3n], [4, [4, 0, 0, 0, 0, 0, 0, 0], 4n],
  [9, [127], -1n], [10, [255, 255], -1n], [11, [255, 255, 255, 255], -1n],
  [12, [255, 255, 255, 255, 255, 255, 255, 255], -1n]
] as const) {
  void test(`reads unwind pointer encoding ${encoding}`, async () => {
    const { cursor, issues } = unwindCursor([...bytes]);
    assert.deepEqual(await readElfUnwindPointer(cursor, encoding, 4, 0n),
      { address: expected, indirect: false });
    assert.deepEqual(issues, []);
  });
}

void test("preserves indirect PC-relative pointers and encoded null", async () => {
  const { cursor } = unwindCursor([4, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(await readElfUnwindPointer(cursor, 0x93, 8, 100n),
    { address: 104n, indirect: true });
  assert.deepEqual(await readElfUnwindPointer(cursor, 0x13, 8, 100n),
    { address: 0n, indirect: false });
  assert.equal(await readElfUnwindPointer(cursor, 0xff, 8, 0n), null);
});

void test("reports unsupported formats and bases", async () => {
  const first = unwindCursor([1]);
  assert.equal(await readElfUnwindPointer(first.cursor, 7, 8, 0n), null);
  assert.match(first.issues.join(" "), /format/);
  const second = unwindCursor([1]);
  assert.equal(await readElfUnwindPointer(second.cursor, 0x30, 8, 0n), null);
  assert.match(second.issues.join(" "), /base/);
});

void test("reports truncated fixed width pointers", async () => {
  const { cursor, issues } = unwindCursor([1]);
  assert.equal(await readElfUnwindPointer(cursor, 3, 8, 0n), null);
  assert.ok(issues.length > 0);
});

void test("a zero PC-relative set_loc displacement names the encoded field address", async () => {
  const { cursor, issues } = unwindCursor([0, 0, 0, 0]);

  // DW_EH_PE_pcrel | DW_EH_PE_sdata4 preserves the field address for a zero displacement.
  assert.equal(await readElfUnwindLocation(cursor, 0x1b, 8, 1024n), 1024n);
  assert.deepEqual(issues, []);
});

void test("set_loc cannot resolve indirect encodings or read beyond the CFI record", async () => {
  const indirect = unwindCursor([0, 0, 0, 0]);
  const truncated = unwindCursor([0, 0, 0]);

  // 0x80 is DW_EH_PE_indirect on the PC-relative signed encoding used above.
  assert.equal(await readElfUnwindLocation(indirect.cursor, 0x9b, 8, 1024n), null);
  assert.match(indirect.issues.join(" "), /direct address/);
  assert.equal(await readElfUnwindLocation(truncated.cursor, 0x1b, 8, 1024n), null);
  assert.match(truncated.issues.join(" "), /Truncated/);
});
