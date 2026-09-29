import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture, createRttiOnlyFixture } from "../../../fixtures/itanium-rtti.js";

for (const width of [4, 8] as const) {
  void test(`reserves ${width}-byte RTTI with a name longer than 511 bytes`, async () => {
    const fixture = createRttiOnlyFixture(width);
    fixture.type(fixture.addresses.multiple, fixture.addresses.vmiTable,
      "16RttiOnlyTemplateI" + "i".repeat(1024) + "E");

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.vtables.some(table => table.address === fixture.falseAddressPoint), false);
    assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
    assert.deepEqual(result.warnings, []);
  });
}

for (const width of [4, 8] as const) {
  for (const name of ["16RttiOnlyTemplateIiE", "N2ns16RttiOnlyTemplateIiEE", "Z1fvE5Local", "2\u00c9"]) {
    void test(`reserves ${width}-byte RTTI with unsupported name ${name}`, async () => {
      const fixture = createRttiOnlyFixture(width);
      fixture.type(fixture.addresses.multiple, fixture.addresses.vmiTable, name);

      const result = await discoverItaniumRtti(fixture.image);

      assert.ok(result);
      assert.equal(result.vtables.some(table => table.address === fixture.falseAddressPoint), false);
      assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
      assert.deepEqual(result.warnings, []);
    });
  }
  void test(`reserves ${width}-byte VMI with unsupported base names`, async () => {
    const fixture = createRttiOnlyFixture(width);
    fixture.type(1024, fixture.addresses.classTable, "6EmptyAIiE");

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.vtables.some(table => table.address === fixture.falseAddressPoint), false);
    assert.equal(result.types.some(type => [1024, 1056, fixture.addresses.multiple].includes(type.address)), false);
  });
}

void test("does not publish a supported derived type with an unsupported base name", async () => {
  const fixture = createItaniumFixture();
  fixture.type(fixture.addresses.base, fixture.addresses.classTable, "4BaseIiE");

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.equal(result.types.some(type => [fixture.addresses.base, fixture.addresses.derived,
    fixture.addresses.multiple].includes(type.address)), false);
  assert.equal(result.vtables.some(table => table.address === fixture.addresses.siObjectTable), false);
});

type Fixture = ReturnType<typeof createRttiOnlyFixture>;
void test("omits all vtables if a standalone VMI exceeds the base validation budget", async () => {
  const fixture = createRttiOnlyFixture(8);
  fixture.view.setUint32(fixture.addresses.multiple + 20, 257, true);

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.deepEqual(result.vtables, []);
  assert.deepEqual(result.types, []);
  assert.match(result.warnings.join(), /base count limit/);
});

void test("omits all vtables when the structural name scan cannot finish within its budget", async () => {
  const fixture = createRttiOnlyFixture(8);
  const read = fixture.image.read;
  fixture.pointer(fixture.addresses.multiple + 8, 65536);
  fixture.image.read = (address, size) => address >= 65536
    ? Promise.resolve(new DataView(new Uint8Array(size).fill(65).buffer)) : read(address, size);

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.deepEqual(result.vtables, []);
  assert.deepEqual(result.types, []);
  assert.match(result.warnings.join(), /name validation budget exhausted/);
});

for (const [label, edit] of Object.entries({
  empty: (fixture: Fixture) => fixture.type(fixture.addresses.multiple, fixture.addresses.vmiTable, ""),
  missingPointer: (fixture: Fixture) => fixture.image.pointers.delete(fixture.addresses.multiple + 8),
  unmapped: (fixture: Fixture) => fixture.pointer(fixture.addresses.multiple + 8, fixture.bytes.length),
  unterminated: (fixture: Fixture) => {
    fixture.pointer(fixture.addresses.multiple + 8, fixture.bytes.length - 512);
    fixture.bytes.fill(65, fixture.bytes.length - 512);
  },
  truncated: (fixture: Fixture) => {
    fixture.pointer(fixture.addresses.multiple + 8, fixture.bytes.length - 1);
    fixture.bytes[fixture.bytes.length - 1] = 65;
  }
})) {
  void test(`does not reserve metadata whose NTBS is structurally invalid (${label})`, async () => {
    const fixture = createRttiOnlyFixture(8);
    edit(fixture);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.ok(result.vtables.some(table => table.address === fixture.falseAddressPoint));
    assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
    assert.deepEqual(result.warnings, []);
  });
}
