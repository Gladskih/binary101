import assert from "node:assert/strict";
import { test } from "node:test";
import { createItaniumRecords } from "../../../../analyzers/itanium-rtti/records.js";
import { findItaniumRuntime } from "../../../../analyzers/itanium-rtti/runtime.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

type Fixture = ReturnType<typeof createItaniumFixture>;
for (const slot of [0, 8]) {
  for (const [target, edit] of Object.entries({
    missing: (fixture: Fixture, site: number) => fixture.image.pointers.delete(site),
    data: (fixture: Fixture, site: number) => fixture.pointer(site, fixture.addresses.base)
  })) {
    void test(`bootstrap still rejects ${target} function evidence at slot ${slot}`, async () => {
      const fixture = createItaniumFixture();
      edit(fixture, fixture.addresses.classTable + slot);

      const kinds = await findItaniumRuntime(fixture.image, createItaniumRecords(fixture.image));

      assert.equal(kinds.size, 0);
    });
  }
}
void test("identifies runtime kinds through their closed metadata graph", async () => {
  const fixture = createItaniumFixture();
  assert.deepEqual(await findItaniumRuntime(fixture.image, createItaniumRecords(fixture.image)),
    new Map([[fixture.addresses.classTable, "class"], [fixture.addresses.siTable, "si"],
      [fixture.addresses.vmiTable, "vmi"]]));
});
for (const [label, edit] of Object.entries({
  noSiPointer: (fixture: Fixture) => fixture.image.pointers.delete(fixture.addresses.classMeta),
  sameTable: (fixture: Fixture) => fixture.pointer(fixture.addresses.classMeta, fixture.addresses.classTable),
  noSiTable: (fixture: Fixture) => fixture.image.pointers.delete(fixture.addresses.siTable),
  siName: (fixture: Fixture) => fixture.type(fixture.addresses.siMeta, fixture.addresses.siTable, "4Fake"),
  siCycle: (fixture: Fixture) => fixture.pointer(fixture.addresses.siMeta, fixture.addresses.classTable),
  noSiBase: (fixture: Fixture) => fixture.image.pointers.delete(fixture.addresses.siMeta + 16),
  noStdBase: (fixture: Fixture) => fixture.image.pointers.delete(fixture.addresses.classMeta + 16),
  stdName: (fixture: Fixture) => fixture.type(fixture.addresses.stdMeta, fixture.addresses.classTable, "4Fake"),
  stdCycle: (fixture: Fixture) => fixture.pointer(fixture.addresses.stdMeta, fixture.addresses.siTable)
})) {
  void test(`rejects runtime with broken ${label}`, async () => {
    const fixture = createItaniumFixture();
    edit(fixture);
    assert.equal((await findItaniumRuntime(fixture.image,
      createItaniumRecords(fixture.image))).size, 0);
  });
}

for (const key of ["classMeta", "siMeta", "vmiMeta"] as const) {
  void test(`rejects a truncated runtime ${key} body`, async () => {
    const fixture = createItaniumFixture();
    const read = fixture.image.read;
    fixture.image.read = (address, size) => read(address,
      address === fixture.addresses[key] && size === 24 ? 16 : size);
    const kinds = await findItaniumRuntime(fixture.image, createItaniumRecords(fixture.image));
    assert.equal(kinds.has(fixture.addresses.vmiTable), false);
  });
}
for (const [label, edit] of Object.entries({
  noSiPointer: (fixture: Fixture) => fixture.image.pointers.delete(fixture.addresses.vmiMeta),
  wrongSiPointer: (fixture: Fixture) => fixture.pointer(fixture.addresses.vmiMeta, fixture.addresses.classTable),
  wrongBase: (fixture: Fixture) => fixture.pointer(fixture.addresses.vmiMeta + 16, fixture.addresses.stdMeta)
})) {
  void test(`rejects VMI runtime with ${label}`, async () => {
    const fixture = createItaniumFixture();
    edit(fixture);
    assert.equal((await findItaniumRuntime(fixture.image,
      createItaniumRecords(fixture.image))).has(fixture.addresses.vmiTable), false);
  });
}
