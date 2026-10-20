import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfCrelRelocations } from "../../../../analyzers/elf/relocation-crel.js";
import { packedRelocationFixture, encodeUnsigned, encodeSigned } from "../../../fixtures/elf-packed-relocations.js";

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`CREL ELF${bits} ${order} state and negative deltas`, async () => {
      // count=2, explicit addends, shift=2; offset deltas 2 and 1.
      const fixture = packedRelocationFixture([22, 23, 2, 3, 0x7c, 15, 0x7f, 0x7f, 7], bits, order);
      const entries = await Array.fromAsync(readElfCrelRelocations(fixture.stream, fixture.elf, 4));
      assert.deepEqual(entries.map(entry => [entry.offset, entry.symbolIndex, entry.type, entry.addend]),
        [[8n, 2, 3, -4n], [12n, 1, 2, 3n]]);
      assert.equal(entries[0]?.recordOffset, 65);
      assert.equal(entries[0]?.tableIndex, 4);
      assert.equal(fixture.stream.position, fixture.stream.end);
    });
  }
}
void test("CREL continuation offsets and implicit addends", async () => {
  const fixture = packedRelocationFixture([16, 0x83, 1, 1, 2, 4]);
  const entries = await Array.fromAsync(readElfCrelRelocations(fixture.stream, fixture.elf, 0));
  assert.deepEqual(entries.map(entry => [entry.offset, entry.type, entry.addend]), [[32n, 2, null], [33n, 2, null]]);
});
void test("CREL wraps ABI accumulators and supports offsets above 64 encoded bits", async () => {
  const fixture = packedRelocationFixture([12, 0x87, ...encodeUnsigned((1n << 64n) - 1n),
    ...encodeSigned(-1n), ...encodeSigned(-1n), ...encodeSigned(-(1n << 63n))]);
  const entries = await Array.fromAsync(readElfCrelRelocations(fixture.stream, fixture.elf, 0));
  assert.equal(entries[0]?.offset, (1n << 64n) - 16n);
  assert.equal(entries[0]?.symbolIndex, 0xffffffff);
  assert.equal(entries[0]?.type, 0xffffffff);
  assert.equal(entries[0]?.addend, -(1n << 63n));
});
void test("CREL empty headers and implicit addend flag bits stay separate", async () => {
  const empty = packedRelocationFixture([0]);
  const implicit = packedRelocationFixture([8, 4]);
  assert.deepEqual(await Array.fromAsync(readElfCrelRelocations(empty.stream, empty.elf, 0)), []);
  const entries = await Array.fromAsync(readElfCrelRelocations(implicit.stream, implicit.elf, 0));
  assert.equal(entries[0]?.offset, 1n);
  assert.equal(entries[0]?.addend, null);
});
void test("CREL rejects impossible counts and incomplete symbol/addend fields", async () => {
  const count = packedRelocationFixture([16, 0]);
  const symbol = packedRelocationFixture([8, 1]);
  const addend = packedRelocationFixture([12, 4]);
  await assert.rejects(Array.fromAsync(readElfCrelRelocations(count.stream, count.elf, 0)), /truncated CREL/);
  await assert.rejects(Array.fromAsync(readElfCrelRelocations(symbol.stream, symbol.elf, 0)), /truncated packed/);
  await assert.rejects(Array.fromAsync(readElfCrelRelocations(addend.stream, addend.elf, 0)), /truncated packed/);
});
