import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotDispatchMaps } from "../../../../analyzers/native-aot/dispatch-map.js";
import { createNativeAotRuntimeTailFixture } from "../../../helpers/native-aot-runtime-tail-fixture.js";

void test("dispatch maps retain all four groups and cache shared data", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  const reader = new NativeAotDispatchMaps(fixture.references);
  const reads = context.mock.method(fixture.image, "readData");

  const map = await reader.read(fixture.dispatchRva);
  const count = reads.mock.callCount();

  assert.deepEqual(map?.counts, [2, 1, 1, 1]);
  assert.deepEqual(map?.entries.map(entry => entry.kind), ["standard", "standard", "default", "static", "default static"]);
  assert.equal(await reader.read(fixture.dispatchRva), map);
  assert.equal(reads.mock.callCount(), count);
  assert.deepEqual([...fixture.issues], []);
});

for (const target of [0x261, 0x300, 0x400]) {
  void test(`rejects and caches invalid dispatch map address ${target}`, async context => {
    const fixture = createNativeAotRuntimeTailFixture();
    const reader = new NativeAotDispatchMaps(fixture.references);
    const reads = context.mock.method(fixture.image, "readData");

    assert.equal(await reader.read(target), null);
    assert.equal(await reader.read(target), null);
    assert.equal(reads.mock.callCount(), 0);
    assert.match([...fixture.issues].join(), /mapped range or alignment/);
  });
}

void test("truncated entries retain complete records and the declared counts", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  context.mock.method(fixture.image, "isMappedRange", (address: number, size: number) =>
    address >= 0 && address + size <= fixture.dispatchRva + 15);

  const map = await new NativeAotDispatchMaps(fixture.references).read(fixture.dispatchRva);

  assert.deepEqual(map?.counts, [2, 1, 1, 1]);
  assert.equal(map?.entries.length, 1);
  assert.match([...fixture.issues].join(), /mapped range/);
});

void test("a dispatch record must fit one mapped range even when its separate scalars are readable", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  context.mock.method(fixture.image, "isMappedRange", (address: number, size: number) =>
    address !== fixture.dispatchRva + 14 || size !== 6);

  const map = await new NativeAotDispatchMaps(fixture.references).read(fixture.dispatchRva);

  assert.equal(map?.entries.length, 1);
  assert.match([...fixture.issues].join(), /mapped range/);
});

void test("unreadable counts and typed or untyped I/O failures are warnings", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  context.mock.method(fixture.references.data, "unsigned", async () => null);

  assert.equal(await new NativeAotDispatchMaps(fixture.references).read(fixture.dispatchRva), null);
  assert.match([...fixture.issues].join(), /truncated or unreadable/);
  context.mock.method(fixture.references.data, "unsigned", async () => { throw "failure"; });
  assert.equal(await new NativeAotDispatchMaps(fixture.references).read(fixture.dispatchRva), null);
  assert.match([...fixture.issues].join(), /dispatch map read failed/);
});

void test("empty maps are valid and the full ushort entry count is parsed without a cap", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  context.mock.method(fixture.references.data, "unsigned", async () => 0);
  const empty = await new NativeAotDispatchMaps(fixture.references).read(fixture.dispatchRva);
  assert.deepEqual(empty, { rva: fixture.dispatchRva, counts: [0, 0, 0, 0], entries: [] });
  context.mock.method(fixture.image, "isMappedRange", () => true);
  context.mock.method(fixture.references.data, "unsigned", async (address: number) =>
    address === fixture.dispatchRva ? 65535 : 0);

  const full = await new NativeAotDispatchMaps(fixture.references).read(fixture.dispatchRva);

  assert.equal(full?.entries.length, 65535);
  assert.equal(full?.entries.at(-1)?.implementationSlot, 0);
  assert.deepEqual([...fixture.issues], []);
});
