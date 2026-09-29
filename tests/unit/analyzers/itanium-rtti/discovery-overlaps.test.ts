import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

const addNullTable = (
  fixture: ReturnType<typeof createItaniumFixture>, address: number, typeAddress: number
): void => {
  const width = fixture.image.pointerSize;
  for (const site of [address - 2 * width, address]) {
    fixture.image.pointers.delete(site);
    fixture.image.relocations.delete(site);
    fixture.word(site, 0n);
  }
  fixture.pointer(address - width, typeAddress);
};

for (const width of [4, 8] as const) {
  for (const count of [2, 3]) {
    void test(`omits all ${count} overlapping ${width}-byte primary vtable candidates`, async () => {
      const fixture = createItaniumFixture(width);
      const addresses = Array.from({ length: count }, (_, index) => fixture.addresses.table + index * 2 * width);
      addresses.forEach(address => addNullTable(fixture, address, fixture.addresses.base));
      fixture.image.readOrder = address => fixture.bytes.length - address;

      const result = await discoverItaniumRtti(fixture.image);

      assert.ok(result);
      assert.equal(result.vtables.some(table => addresses.includes(table.address)), false);
      assert.ok(result.vtables.some(table => table.address === fixture.addresses.vmiObjectTable));
      assert.deepEqual(result.warnings, []);
    });
  }
  void test(`does not prefer the final ${width}-byte candidate with a code pointer`, async () => {
    const fixture = createItaniumFixture(width);
    const first = fixture.addresses.table;
    const second = first + 2 * width;
    addNullTable(fixture, first, fixture.addresses.base);
    addNullTable(fixture, second, fixture.addresses.base);
    fixture.pointer(second, fixture.addresses.code);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.vtables.some(table => [first, second].includes(table.address)), false);
  });
  void test(`accepts adjacent non-overlapping ${width}-byte minimum vtable ranges`, async () => {
    const fixture = createItaniumFixture(width);
    const first = fixture.addresses.table;
    const second = first + 3 * width;
    addNullTable(fixture, first, fixture.addresses.base);
    addNullTable(fixture, second, fixture.addresses.base);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result?.vtables.some(table => table.address === first));
    assert.ok(result?.vtables.some(table => table.address === second));
  });
}

void test("unsupported name syntax does not conceal an overlapping structural candidate", async () => {
  const fixture = createItaniumFixture();
  fixture.type(1024, fixture.addresses.classTable, "3FooIiE");
  addNullTable(fixture, fixture.addresses.table, 1024);
  addNullTable(fixture, fixture.addresses.table + 16, fixture.addresses.base);

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result);
  assert.equal(result.vtables.some(table => table.address === fixture.addresses.table + 16), false);
});

void test("a candidate with an invalid type does not invalidate its valid neighbor", async () => {
  const fixture = createItaniumFixture();
  addNullTable(fixture, fixture.addresses.table, fixture.addresses.base);
  addNullTable(fixture, fixture.addresses.table + 16, fixture.bytes.length);

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result?.vtables.some(table => table.address === fixture.addresses.table));
  assert.equal(result?.vtables.some(table => table.address === fixture.addresses.table + 16), false);
});

void test("returns no analysis when every candidate has an overlapping neighbor", async () => {
  const fixture = createItaniumFixture();
  const { classTable, siTable, vmiTable, table, siObjectTable, vmiObjectTable, base } = fixture.addresses;
  for (const address of [classTable, siTable, vmiTable]) addNullTable(fixture, address - 16, base);
  for (const address of [table, siObjectTable, vmiObjectTable]) {
    fixture.image.pointers.delete(address - 8);
    fixture.image.relocations.delete(address - 8);
  }

  assert.equal(await discoverItaniumRtti(fixture.image), null);
});
