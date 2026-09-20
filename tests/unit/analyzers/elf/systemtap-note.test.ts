import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeSystemTapNote } from "../../../../analyzers/elf/systemtap-note.js";

const descriptor = (width: 4 | 8, order: "little" | "big"): Uint8Array => {
  const bytes = new Uint8Array(width * 3 + 9);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < 3; index++) {
    if (width === 8) view.setBigUint64(index * width, BigInt(index + 1), order === "little");
    else view.setUint32(index * width, index + 1, order === "little");
  }
  bytes.set(new TextEncoder().encode("lib\0test\0"), width * 3);
  return new Uint8Array([...bytes, 0]);
};

for (const width of [4, 8] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`SystemTap ${width}-byte ${order}-endian addresses`, () => {
      const issues: string[] = [];
      assert.equal(decodeSystemTapNote(descriptor(width, order), width, order, issues),
        "lib:test; location 0x1; base 0x2; semaphore 0x3; arguments: none");
      assert.deepEqual(issues, []);
    });
  }
}

for (const length of [0, 23, 24, 27, 32]) {
  void test(`SystemTap rejects truncation at byte ${length}`, () => {
    const issues: string[] = [];
    assert.equal(decodeSystemTapNote(descriptor(8, "little").subarray(0, length), 8, "little", issues), null);
    assert.equal(issues.length, 1);
  });
}
