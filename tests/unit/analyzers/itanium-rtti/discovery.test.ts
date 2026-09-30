import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture, createRttiOnlyFixture } from "../../../fixtures/itanium-rtti.js";

type RttiOnlyFixture = ReturnType<typeof createRttiOnlyFixture>;
for (const [label, edit] of Object.entries({
  missingRelocation: (fixture: RttiOnlyFixture) => fixture.image.relocations.delete(fixture.addresses.multiple),
  unknownRuntime: (fixture: RttiOnlyFixture) => fixture.pointer(fixture.addresses.multiple, fixture.addresses.table),
  emptyName: (fixture: RttiOnlyFixture) => fixture.type(fixture.addresses.multiple, fixture.addresses.vmiTable, ""),
  invalidCount: (fixture: RttiOnlyFixture) => {
    // Nonzero flags prevent the flags/count word from becoming an overlapping vtable header.
    fixture.view.setUint32(fixture.addresses.multiple + 16, 1, true);
    fixture.view.setUint32(fixture.addresses.multiple + 20, 0, true);
  },
  invalidBase: (fixture: RttiOnlyFixture) => fixture.pointer(fixture.addresses.multiple + 24, 4000),
  truncatedHeader: (fixture: RttiOnlyFixture) => {
    const read = fixture.image.read;
    fixture.image.read = (address, size) => read(address,
      address === fixture.addresses.multiple ? 8 : size);
  }
})) {
  void test(`rejects malformed standalone RTTI (${label})`, async () => {
    const fixture = createRttiOnlyFixture(8);
    edit(fixture);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.types.some(type => type.name === "8RttiOnly"), false);
    assert.deepEqual(result.warnings, []);
  });
}

for (const width of [4, 8] as const) {
  void test(`parses a closed runtime and class graph with ${width}-byte pointers`, async () => {
    const fixture = createItaniumFixture(width);
    const result = await discoverItaniumRtti(fixture.image);
    assert.equal(result?.types.find(row => row.address === fixture.addresses.base)?.name, "4Base");
    assert.deepEqual(result?.types.find(row => row.address === fixture.addresses.derived)?.bases,
      [{ typeAddress: fixture.addresses.base, offset: 0, isVirtual: false, isPublic: true }]);
    assert.deepEqual(result?.types.find(row => row.address === fixture.addresses.multiple)?.bases,
      [{ typeAddress: fixture.addresses.base, offset: -3 * width, isVirtual: true, isPublic: true }]);
    assert.deepEqual(result?.warnings, []);
  });
}

void test("rejects an unclosed runtime graph", async () => {
  const fixture = createItaniumFixture();
  fixture.image.pointers.delete(fixture.addresses.siMeta + 16);
  assert.equal(await discoverItaniumRtti(fixture.image), null);
});

void test("ignores ordinary bytes without relocation evidence", async () => {
  const fixture = createItaniumFixture();
  fixture.image.pointers.clear();
  assert.equal(await discoverItaniumRtti(fixture.image), null);
});

void test("publishes a separately validated base even when a referring derived type is invalid", async () => {
  const fixture = createItaniumFixture();
  fixture.type(1024, fixture.addresses.classTable, "6Orphan");
  fixture.view.setUint32(fixture.addresses.multiple + 20, 2, true);
  fixture.pointer(fixture.addresses.multiple + 24, 1024);
  fixture.pointer(fixture.addresses.multiple + 40, 1080);
  const result = await discoverItaniumRtti(fixture.image);
  assert.ok(result);
  assert.equal(result.types.some(type => type.name === "6Orphan"), true);
  assert.equal(result.types.some(type => type.name === "8Multiple"), false);
  assert.deepEqual(result.warnings, []);
});

void test("rejects cyclic inheritance silently", async () => {
  const fixture = createItaniumFixture();
  fixture.pointer(fixture.addresses.derived + 16, fixture.addresses.derived);
  const result = await discoverItaniumRtti(fixture.image);
  assert.ok(result);
  assert.equal(result.types.some(type => type.name === "7Derived"), false);
  assert.deepEqual(result.warnings, []);
});

void test("rejects an unsupported name and invalid VMI body silently", async () => {
  const fixture = createItaniumFixture();
  fixture.type(fixture.addresses.derived, fixture.addresses.siTable, "3FooIiE");
  fixture.view.setUint32(fixture.addresses.multiple + 20, 0, true);
  const result = await discoverItaniumRtti(fixture.image);
  assert.ok(result);
  assert.equal(result.types.some(type => type.address === fixture.addresses.derived), false);
  assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
  assert.deepEqual(result.warnings, []);
});

void test("bounds deep inheritance without overflowing the stack", async () => {
  const fixture = createItaniumFixture();
  const chain = Array.from({ length: 65 }, (_, index) => 2000 + index * 24);
  chain.forEach((address, index) => {
    fixture.type(address, fixture.addresses.siTable, "4Deep");
    fixture.pointer(address + 16, chain[index + 1] ?? fixture.addresses.base);
  });
  fixture.table(fixture.addresses.table, chain[0]!);
  const result = await discoverItaniumRtti(fixture.image);
  assert.ok(result);
  assert.equal(result.types.some(type => type.address === chain[0]), false);
  assert.match(result.warnings.join(), /depth limit/);
  assert.ok(result.types.some(type => type.name === "4Base"));
});
