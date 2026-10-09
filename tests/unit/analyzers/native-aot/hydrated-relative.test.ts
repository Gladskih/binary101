import assert from "node:assert/strict";
import test from "node:test";
import { readNativeAotHydratedRelative as read } from "../../../../analyzers/native-aot/hydrated-relative.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("relative fields use the destination address, including copied signed displacements", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  fixture.view.setInt32(0x240, -0x140, true);

  assert.equal(await read(fixture.image, [{ kind: "copy", rva: 0x180, size: 4, sourceRva: 0x240 }], 0x180), 0x40);
  assert.equal(await read(fixture.image, [{ kind: "relative", rva: 0x180, size: 4, target: 0x300 }], 0x180), 0x300);
  assert.equal(await read(fixture.image, [{ kind: "zero", rva: 0x180, size: 4 }], 0x180), 0x180);
  fixture.view.setInt32(0x180, 0x180, true);
  assert.equal(await read(fixture.image, [], 0x180), 0x300);
});

void test("relative fields span scalar runs but reject absolute relocations and interior typed fields", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  fixture.bytes[0x240] = 1;

  assert.equal(await read(fixture.image, [
    { kind: "copy", rva: 0x180, size: 1, sourceRva: 0x240 },
    { kind: "zero", rva: 0x181, size: 3 }
  ], 0x180), 0x181);
  await assert.rejects(read(fixture.image, [{ kind: "pointer", rva: 0x180, size: 8, target: 0x300 }], 0x180),
    /not a relative pointer/);
  await assert.rejects(read(fixture.image, [{ kind: "relative", rva: 0x17c, size: 8, target: 0x300 }], 0x180),
    /complete relative field/);
});

void test("relative reads validate coordinates, complete storage and safe target arithmetic", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());

  await assert.rejects(read(fixture.image, [], -4), /mapped range/);
  await assert.rejects(read(fixture.image, [], 0x181), /mapped range/);
  await assert.rejects(read(fixture.image, [], 0x400), /mapped range/);
  await assert.rejects(read(fixture.image, [], Number.NaN), /mapped range/);
  context.mock.method(fixture.image, "readData", async () => null);
  await assert.rejects(read(fixture.image, [], 0x180), /unreadable/);
  context.mock.method(fixture.image, "isMappedRange", () => true);
  context.mock.method(fixture.image, "readData", async (address: number) =>
    new DataView(Uint8Array.of(address % 4 === 3 ? 127 : 255).buffer));
  await assert.rejects(read(fixture.image, [], Number.MAX_SAFE_INTEGER - 3), /invalid target/);
});

void test("typed relocations independently reject invalid caller coordinates and incomplete fields", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  context.mock.method(fixture.image, "isMappedRange", () => true);

  await assert.rejects(read(fixture.image, [{ kind: "relative", rva: -4, size: 4, target: 0x40 }], -4), /mapped range/);
  await assert.rejects(read(fixture.image, [{ kind: "relative", rva: 1e20, size: 4, target: 0x40 }], 1e20), /mapped range/);
  await assert.rejects(read(fixture.image, [{ kind: "relative", rva: 0x180, size: 8, target: 0x40 }], 0x180),
    /complete relative field/);
  await assert.rejects(read(fixture.image, [{ kind: "relative", rva: 0x17e, size: 4, target: 0x40 }], 0x180),
    /complete relative field/);
  assert.equal(await read(fixture.image, [{ kind: "relative", rva: 0, size: 4, target: 0 }], 0), 0);
});

void test("signed Int32 minimum and zero image targets have exact boundary semantics", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  fixture.view.setInt32(0x180, -0x180, true);

  assert.equal(await read(fixture.image, [], 0x180), 0);
  fixture.view.setInt32(0x180, -0x184, true);
  await assert.rejects(read(fixture.image, [], 0x180), /invalid target/);
  context.mock.method(fixture.image, "isMappedRange", () => true);
  context.mock.method(fixture.image, "readData", async (address: number) =>
    new DataView(Uint8Array.of(address % 4 === 3 ? 128 : 0).buffer));
  // The signed Int32 minimum (-2^31), when stored at RVA 2^31, resolves to RVA zero.
  assert.equal(await read(fixture.image, [], 0x80000000), 0);
});
