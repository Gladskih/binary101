import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture, createRttiOnlyFixture } from "../../../fixtures/itanium-rtti.js";

for (const width of [4, 8] as const) {
  void test(`omits unsupported ${width}-byte RTTI with a long unsupported template name`, async () => {
    const fixture = createRttiOnlyFixture(width);
    fixture.type(fixture.addresses.multiple, fixture.addresses.vmiTable,
      "16RttiOnlyTemplateI" + "i".repeat(1024) + "E");

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
    assert.deepEqual(result.warnings, []);
  });
}

for (const width of [4, 8] as const) {
  for (const name of ["16RttiOnlyTemplateIiE", "N2ns16RttiOnlyTemplateIiEE", "Z1fvE5Local", "2\u00c9"]) {
    void test(`omits unsupported ${width}-byte RTTI with unsupported name ${name}`, async () => {
      const fixture = createRttiOnlyFixture(width);
      fixture.type(fixture.addresses.multiple, fixture.addresses.vmiTable, name);

      const result = await discoverItaniumRtti(fixture.image);

      assert.ok(result);
      assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
      assert.deepEqual(result.warnings, []);
    });
  }
  void test(`omits unsupported ${width}-byte VMI with unsupported base names`, async () => {
    const fixture = createRttiOnlyFixture(width);
    fixture.type(1024, fixture.addresses.classTable, "6EmptyAIiE");

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.types.some(type => [1024, fixture.addresses.multiple].includes(type.address)), false);
  });
}

void test("does not publish a supported derived type with an unsupported base name", async () => {
  const fixture = createItaniumFixture();
  fixture.type(fixture.addresses.base, fixture.addresses.classTable, "4BaseIiE");

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.equal(result.types.some(type => [fixture.addresses.base, fixture.addresses.derived,
    fixture.addresses.multiple].includes(type.address)), false);
});

type Fixture = ReturnType<typeof createRttiOnlyFixture>;
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
  void test(`omits a type whose NTBS is structurally invalid (${label})`, async () => {
    const fixture = createRttiOnlyFixture(8);
    edit(fixture);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.types.some(type => type.address === fixture.addresses.multiple), false);
    assert.deepEqual(result.warnings, []);
  });
}
