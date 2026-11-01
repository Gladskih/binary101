import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeRelocationCandidates } from "../../../../analyzers/pe/relocation-candidates.js";
import {
  nativeDiscovery, msvcDiscovery, sparseNativeDiscovery, boundaryMsvcDiscovery, crossedMsvcDiscovery
} from "../../../helpers/pe-relocation-discovery.js";

for (const width of [4, 8] as const) {
  void test(`collects PE${width * 8} candidates and pointer evidence in one source read`, async () => {
    const { fixture, reader, state } = nativeDiscovery(width);
    const reads: number[] = [];
    const read = reader.read.bind(reader);
    reader.read = (offset, size) => { reads.push(offset); return read(offset, size); };
    await collectPeRelocationCandidates(state);
    assert.deepEqual(reads, [fixture.modulePointerRva - 0x1000]);
    assert.equal(state.nativeCandidates.get(fixture.modulePointerRva), fixture.headerRva);
    assert.equal(state.itaniumImage.pointers.get(fixture.modulePointerRva), fixture.headerRva);
    assert.deepEqual(state.itaniumImage.relocations, new Set(state.sites));
  });
}

void test("collects validated MSVC seeds without rereading adjacent pointers", async () => {
  const { state, vftable } = msvcDiscovery();
  await collectPeRelocationCandidates(state);
  assert.deepEqual(state.msvcCandidates, [{ locatorSlotRva: vftable.locatorSlotRva,
    locatorRva: vftable.colRva, firstFunctionTargetRva: vftable.functionTargetRvas[0] }]);
});

for (const value of [0n, 0xffffffffffffffffn]) {
  void test(`rejects a pointer outside the image: ${value}`, async () => {
    const { fixture, state } = nativeDiscovery();
    fixture.view.setBigUint64(0x80, value, true);
    await collectPeRelocationCandidates(state);
    assert.equal(state.nativeCandidates.has(fixture.modulePointerRva), false);
    assert.equal(state.itaniumImage.pointers.has(fixture.modulePointerRva), false);
  });
}

void test("retains an image-relative zero target and skips unreadable source sites", async () => {
  const { fixture, state } = nativeDiscovery();
  fixture.view.setBigUint64(0x80, fixture.core.opt.ImageBase, true);
  state.sites.unshift(0x9000);
  await collectPeRelocationCandidates(state);
  assert.equal(state.itaniumImage.pointers.get(fixture.modulePointerRva), 0);
  assert.equal(state.nativeCandidates.has(fixture.modulePointerRva), false);
  assert.equal(state.itaniumImage.relocations.has(0x9000), true);
});

void test("reports source truncation to the independent-analyzer fallback", async () => {
  const { reader, state } = nativeDiscovery();
  reader.read = async () => new DataView(new ArrayBuffer(0));
  await assert.rejects(collectPeRelocationCandidates(state), /Truncated relocation pointer/);
});

void test("does not accept a data pointer as a vftable function", async () => {
  const { fixture, state, vftable } = msvcDiscovery();
  new DataView(fixture.bytes.buffer).setBigUint64(fixture.rvaToOffset(vftable.rva)!,
    fixture.core.opt.ImageBase + BigInt(vftable.colRva), true);
  await collectPeRelocationCandidates(state);
  assert.equal(state.msvcCandidates.some(candidate => candidate.locatorSlotRva === vftable.locatorSlotRva), false);
});

void test("rejects pointer pairs with an invalid first function target", async () => {
  const { fixture, state, vftable } = msvcDiscovery();
  new DataView(fixture.bytes.buffer).setBigUint64(fixture.rvaToOffset(vftable.rva)!, 0n, true);
  await collectPeRelocationCandidates(state);
  assert.deepEqual(state.msvcCandidates, []);
});

void test("reads sparse sources in physical order with bounded windows", async () => {
  const { state, reader } = sparseNativeDiscovery([0x10070]);
  const ranges: number[][] = [];
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => { ranges.push([offset, size]); return read(offset, size); };
  await collectPeRelocationCandidates(state);
  assert.deepEqual(ranges, [[0x80, 65536], [0x10080, 65536], [0x20080, 0x1f80]]);
  assert.equal(state.nativeCandidates.get(0x21080), 0x1100);
  assert.equal(state.nativeCandidates.get(0x11080), 0x1100);
});

void test("reloads a source window when an adjacent pointer straddles its end", async () => {
  const { state } = sparseNativeDiscovery([0x10078]);
  await collectPeRelocationCandidates(state);
  assert.equal(state.nativeCandidates.get(0x11078), 0x1100);
});

void test("accepts pointer spans ending exactly at the returned view boundary", async () => {
  const { fixture, reader, state } = nativeDiscovery();
  reader.read = async offset => new DataView(fixture.bytes.buffer, offset, 16);
  await collectPeRelocationCandidates(state);
  assert.equal(state.nativeCandidates.get(fixture.modulePointerRva), fixture.headerRva);
});

void test("preserves pairs crossing independent section mappings", async () => {
  const { state, vftable } = boundaryMsvcDiscovery();
  await collectPeRelocationCandidates(state);
  assert.deepEqual(state.boundarySites, [vftable.locatorSlotRva]);
  assert.equal(state.msvcCandidates[0]?.firstFunctionTargetRva, vftable.functionTargetRvas[0]);
});

void test("does not publish rejected boundary candidates", async () => {
  const { state, vftable } = boundaryMsvcDiscovery();
  state.boundarySites.push(0x9000);
  await collectPeRelocationCandidates(state);
  assert.deepEqual(state.msvcCandidates.map(candidate => candidate.locatorSlotRva), [vftable.locatorSlotRva]);
});

void test("reads from nonzero DataView byte offsets", async () => {
  const { fixture, reader, state } = nativeDiscovery();
  reader.read = async (offset, size) => {
    const bytes = new Uint8Array(size + 13);
    bytes.set(fixture.bytes.subarray(offset, offset + size), 13);
    return new DataView(bytes.buffer, 13, size);
  };
  await collectPeRelocationCandidates(state);
  assert.equal(state.nativeCandidates.get(fixture.modulePointerRva), fixture.headerRva);
});

void test("orders MSVC candidates by locator storage rather than source pointer order", async () => {
  const { first, second, state } = crossedMsvcDiscovery();
  await collectPeRelocationCandidates(state);
  assert.deepEqual(state.msvcCandidates.map(candidate => candidate.locatorRva), [first.colRva, second.colRva]);
  assert.deepEqual(state.msvcCandidates.map(candidate => candidate.locatorSlotRva),
    [second.locatorSlotRva, first.locatorSlotRva]);
});
