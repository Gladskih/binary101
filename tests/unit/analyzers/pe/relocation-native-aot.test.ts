import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeRelocationCandidates } from "../../../../analyzers/pe/relocation-candidates.js";
import { analyzePeNativeAotCandidates } from "../../../../analyzers/pe/relocation-native-aot.js";
import { nativeDiscovery, twoNativeHeaders } from "../../../helpers/pe-relocation-discovery.js";

for (const width of [4, 8] as const) {
  void test(`finalizes positive PE${width * 8} metadata and preserves its module pointer`, async () => {
    const { fixture, state } = nativeDiscovery(width);
    await collectPeRelocationCandidates(state);
    const metadata = await analyzePeNativeAotCandidates(state, fixture.core);
    assert.ok(metadata);
    assert.equal(metadata?.status, "confirmed");
    assert.equal(metadata.modulePointerRva, fixture.modulePointerRva);
    assert.equal(metadata.headerRva, fixture.headerRva);
    assert.equal(metadata.majorVersion, 16);
    assert.equal(metadata.sections.length, 2);
  });
}

void test("validates targets in physical order and selects in original relocation order", async () => {
  const { fixture, reader, state } = twoNativeHeaders();
  await collectPeRelocationCandidates(state);
  const calls: number[] = [];
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => { if (size === 16) calls.push(offset); return read(offset, size); };
  const metadata = await analyzePeNativeAotCandidates(state, fixture.core);
  assert.ok(metadata);
  assert.equal(metadata?.headerRva, 0x1500);
  assert.equal(metadata.modulePointerRva, 0x1060);
  assert.ok(calls.indexOf(0x100) < calls.indexOf(0x500));
  assert.equal(calls.filter(offset => offset === 0x300).length, 1);
});

void test("keeps the original first failure before a later valid header", async () => {
  const { fixture, reader, state } = twoNativeHeaders();
  await collectPeRelocationCandidates(state);
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => offset === 0x500 ? Promise.reject(new Error("unreadable")) : read(offset, size);
  assert.equal(await analyzePeNativeAotCandidates(state, fixture.core), null);
});

void test("ignores failure after the original first valid header", async () => {
  const { fixture, reader, state } = twoNativeHeaders();
  await collectPeRelocationCandidates(state);
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => offset === 0x100 ? Promise.reject(new Error("unreadable")) : read(offset, size);
  assert.equal((await analyzePeNativeAotCandidates(state, fixture.core))?.headerRva, 0x1500);
});

void test("decodes shared reflection bytes only after selecting the original first module", async () => {
  const { fixture, reader, state } = twoNativeHeaders();
  await collectPeRelocationCandidates(state);
  const calls: number[][] = [];
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => { calls.push([offset, size]); return read(offset, size); };
  const metadata = await analyzePeNativeAotCandidates(state, fixture.core);
  assert.equal(metadata?.headerRva, 0x1500);
  assert.ok(metadata);
  assert.ok(metadata.reflection);
  assert.equal(calls.filter(([offset, size]) => offset === 0x400 && size === 32).length, 1);
});

void test("returns no result for invalid signatures and missing candidate associations", async () => {
  const { fixture, state } = nativeDiscovery();
  await collectPeRelocationCandidates(state);
  fixture.view.setUint32(0x100, 0, true);
  state.nativeCandidates.delete(fixture.modulePointerRva);
  state.nativeCandidates.set(0x1060, fixture.headerRva);
  assert.equal(await analyzePeNativeAotCandidates(state, fixture.core), null);
});
