import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture, createRttiOnlyFixture } from "../../../fixtures/itanium-rtti.js";

for (const width of [4, 8] as const) {
  void test(`publishes ${width}-byte RTTI-only classes without user vtables`, async () => {
    const fixture = createRttiOnlyFixture(width);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.ok(result.types.some(type => type.name === "8RttiOnly"));
    assert.ok(result.types.some(type => type.name === "6EmptyA"));
    assert.ok(result.types.some(type => type.name === "6EmptyB"));
    assert.deepEqual(Object.keys(result).sort(), ["types", "warnings"]);
  });
  for (const spacing of [2, 4]) {
    void test(`ignores ${width}-byte lookalike vtables separated by ${spacing} words`, async () => {
      const fixture = createItaniumFixture(width);
      const before = await discoverItaniumRtti(fixture.image);
      // Both overlapping and isolated [0, valid type_info*, 0] arrays are ordinary data.
      for (const address of [1600, 1600 + spacing * width]) {
        fixture.pointer(address - width, fixture.addresses.base);
      }

      const result = await discoverItaniumRtti(fixture.image);

      assert.deepEqual(result, before);
      assert.deepEqual(Object.keys(result!).sort(), ["types", "warnings"]);
    });
  }
  void test(`retains all ${width}-byte classes when their user vtables are unreadable`, async () => {
    const fixture = createItaniumFixture(width);
    const before = await discoverItaniumRtti(fixture.image);
    const read = fixture.image.read;
    fixture.image.read = (address, size) => read(address,
      address >= fixture.addresses.table - 3 * width && address < 1024 ? 0 : size);

    const result = await discoverItaniumRtti(fixture.image);

    assert.deepEqual(result?.types, before?.types);
    assert.deepEqual(result?.warnings, []);
  });
}

void test("rejects an unrelocated RTTI vptr even when a validated derived type references it", async () => {
  const fixture = createItaniumFixture();
  fixture.image.relocations.delete(fixture.addresses.base);

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.equal(result.types.some(type => [fixture.addresses.base, fixture.addresses.derived,
    fixture.addresses.multiple].includes(type.address)), false);
  assert.deepEqual(result.warnings, []);
});

void test("publishes types in address order independently of physical read order", async () => {
  const fixture = createItaniumFixture();
  fixture.image.readOrder = address => fixture.bytes.length - address;

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.deepEqual(result.types.map(type => type.address), [fixture.addresses.classMeta,
    fixture.addresses.siMeta, fixture.addresses.vmiMeta, fixture.addresses.stdMeta,
    fixture.addresses.base, fixture.addresses.derived, fixture.addresses.multiple]);
});
