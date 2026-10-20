import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfAndroidRelocations } from "../../../../analyzers/elf/relocation-android.js";
import { androidRelocationFixture, packedRelocationFixture } from "../../../fixtures/elf-packed-relocations.js";

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`APS2 ELF${bits} ${order} grouped fields and addend reset`, async () => {
      // APS2: count, initial offset; group count/flags/delta/info/addend-delta.
      const fixture = androidRelocationFixture([
        3n, 0n, 2n, 15n, 8n, 8n, -4n, 1n, 3n, 0n, 8n
      ], bits, order);
      const entries = await Array.fromAsync(readElfAndroidRelocations(fixture.stream, fixture.elf, "ANDROID_RELA", 7));
      assert.deepEqual(entries.map(entry => [entry.offset, entry.type, entry.addend]),
        [[8n, 8, -4n], [16n, 8, -4n], [16n, 8, 0n]]);
      assert.equal(entries[0]?.tableIndex, 7);
      assert.equal(fixture.stream.position, fixture.stream.end);
    });
  }
}
void test("ungrouped APS2 deltas, symbol indices and implicit REL addends", async () => {
  const fixture = androidRelocationFixture([2n, 0n, 2n, 0n, 8n, 257n, -4n, 258n], 32);
  const entries = await Array.fromAsync(readElfAndroidRelocations(fixture.stream, fixture.elf, "ANDROID_REL", 0));
  assert.deepEqual(entries.map(entry => [entry.offset, entry.type, entry.symbolIndex, entry.addend]),
    [[8n, 1, 1, null], [4n, 2, 1, null]]);
});
void test("ungrouped APS2 explicit addends accumulate per record", async () => {
  const fixture = androidRelocationFixture([2n, 0n, 2n, 8n, 8n, 8n, -4n, 8n, 8n, 7n]);
  const entries = await Array.fromAsync(readElfAndroidRelocations(fixture.stream, fixture.elf, "ANDROID_RELA", 0));
  assert.deepEqual(entries.map(entry => entry.addend), [-4n, 3n]);
});
void test("APS2 supports an empty stream and signed r_info words", async () => {
  const empty = androidRelocationFixture([0n, 0n]);
  const fixture = androidRelocationFixture([1n, 0n, 1n, 3n, 0n, -1n], 32);
  assert.deepEqual(await Array.fromAsync(readElfAndroidRelocations(empty.stream, empty.elf, "ANDROID_REL", 0)), []);
  const entries = await Array.fromAsync(readElfAndroidRelocations(fixture.stream, fixture.elf, "ANDROID_REL", 0));
  assert.equal(entries[0]?.type, 255);
  assert.equal(entries[0]?.symbolIndex, 0xffffff); // ELF32_R_SYM occupies 24 bits.
});
for (const values of [
  [-1n, 0n], [1n, 0n, 0n, 0n], [1n, 0n, 2n, 0n], [1n, 0n, 1n, -1n],
  [1n, 0n, 1n, 16n], [1n, 0n, 1n, 4n], [1n, 0n, 1n, 8n],
  [1n, 0n, 1n, 0n, -1n, 8n], [1n, (1n << 32n) - 1n, 1n, 3n, 1n, 8n]
]) {
  void test(`rejects malformed APS2 fields ${values}`, async () => {
    const fixture = androidRelocationFixture(values, 32);
    await assert.rejects(Array.fromAsync(readElfAndroidRelocations(fixture.stream, fixture.elf, "ANDROID_REL", 0)),
      /negative|invalid|overflows/);
  });
}
void test("rejects APS2 bad magic and incomplete grouped fields", async () => {
  const badMagic = packedRelocationFixture([0]);
  const truncated = androidRelocationFixture([1n, 0n, 1n, 3n, 8n]);
  await assert.rejects(Array.fromAsync(readElfAndroidRelocations(badMagic.stream, badMagic.elf, "ANDROID_REL", 0)), /magic/);
  await assert.rejects(Array.fromAsync(readElfAndroidRelocations(truncated.stream, truncated.elf, "ANDROID_REL", 0)), /truncated/);
});

void test("negative APS2 flags cannot masquerade as all known flag bits", async () => {
  const fixture = androidRelocationFixture([1n, 0n, 1n, -1n, 8n, 8n, 0n]);
  await assert.rejects(Array.fromAsync(readElfAndroidRelocations(fixture.stream, fixture.elf, "ANDROID_RELA", 0)),
    /invalid APS2 group flags/);
});
