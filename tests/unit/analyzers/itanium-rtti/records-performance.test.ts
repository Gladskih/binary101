import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createItaniumRecords } from "../../../../analyzers/itanium-rtti/records.js";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import type { ItaniumRttiImage } from "../../../../analyzers/itanium-rtti/types.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

void test("batches sparse names physically and never repeats the preparation pass", async () => {
  // 32 distant name windows exceed the shared reader's cache; candidate order zigzags.
  const bytes = new Uint8Array(34 * 65536);
  const pointers = new Map<number, number>();
  const names = new TextEncoder().encode("4Base\0");
  for (let index = 0; index < 512; index++) {
    const table = 32 + (511 - index) * 32;
    const type = 65536 + index * 16;
    const name = (2 + index % 32) * 65536 + Math.floor(index / 32) * 16;
    pointers.set(table - 8, type);
    pointers.set(type + 8, name);
    bytes.set(names, name);
  }
  const file = new MockFile(bytes);
  const slice = file.slice.bind(file);
  let physicalReads = 0;
  file.slice = (start, end, type) => { physicalReads++; return slice(start, end, type); };
  const reader = createFileRangeReader(file, 0, file.size);
  const image: ItaniumRttiImage = { pointers, pointerSize: 8, relocations: new Set(pointers.keys()),
    readOrder: address => address, read: reader.read,
    isExecutable: () => assert.fail("Null first slots do not require executable targets") };
  const records = createItaniumRecords(image);
  assert.equal((await records.prepare()).length, 512);
  assert.ok(physicalReads <= 36, `Expected one read per physical window, got ${physicalReads}`);
  const before = physicalReads;
  for (const address of await records.prepare()) await records.table(address);
  assert.equal(physicalReads, before);
});

const createSparseClassFixture = () => {
  const fixture = createItaniumFixture();
  // 512 orphan RTTI objects, reversed insertion order, names spread over 32 distant windows.
  const bytes = new Uint8Array(34 * 65536);
  bytes.set(fixture.bytes);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < 512; index++) {
    const address = 65536 + (511 - index) * 16;
    const name = (2 + index % 32) * 65536 + Math.floor(index / 32) * 16;
    fixture.image.pointers.set(address, fixture.addresses.classTable);
    fixture.image.pointers.set(address + 8, name);
    fixture.image.relocations.add(address);
    fixture.image.relocations.add(address + 8);
    view.setBigUint64(address, BigInt(fixture.addresses.classTable), true);
    view.setBigUint64(address + 8, BigInt(name), true);
    bytes.set(new TextEncoder().encode("6Sparse\0"), name);
  }
  return { fixture, bytes };
};

void test("batches standalone RTTI headers and names independently of user vtables", async () => {
  const { fixture, bytes } = createSparseClassFixture();
  const file = new MockFile(bytes);
  const slice = file.slice.bind(file);
  let physicalReads = 0;
  file.slice = (start, end, type) => { physicalReads++; return slice(start, end, type); };
  fixture.image.read = createFileRangeReader(file, 0, file.size).read;

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.equal(result.types.some(type => type.name === "6Sparse"), false);
  assert.ok(physicalReads <= 36, `Expected ordered RTTI reads, got ${physicalReads}`);
});

const createSparseSiFixture = () => {
  const fixture = createItaniumFixture();
  // Interleaved insertion across 32 type windows and 32 distinct name windows.
  const bytes = new Uint8Array(65 * 65536);
  bytes.set(fixture.bytes);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < 512; index++) {
    const address = (1 + index % 32) * 65536 + Math.floor(index / 32) * 32;
    const name = (33 + index % 32) * 65536 + Math.floor(index / 32) * 16;
    for (const [site, target] of [[address, fixture.addresses.siTable],
      [address + 8, name], [address + 16, fixture.addresses.base]] as const) {
      fixture.image.pointers.set(site, target);
      fixture.image.relocations.add(site);
      view.setBigUint64(site, BigInt(target), true);
    }
    bytes.set(new TextEncoder().encode("6Sparse\0"), name);
  }
  return { fixture, bytes };
};

void test("parses standalone SI bodies in physical order after preparing their names", async () => {
  const { fixture, bytes } = createSparseSiFixture();
  const file = new MockFile(bytes);
  const slice = file.slice.bind(file);
  let physicalReads = 0;
  file.slice = (start, end, type) => { physicalReads++; return slice(start, end, type); };
  fixture.image.read = createFileRangeReader(file, 0, file.size).read;

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.equal(result.types.some(type => type.name === "6Sparse"), false);
  // At most four 32-window passes (candidates, headers, names, bodies), plus bootstrap.
  assert.ok(physicalReads <= 135, `Expected ordered RTTI body reads, got ${physicalReads}`);
});
