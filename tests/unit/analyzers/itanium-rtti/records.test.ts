import assert from "node:assert/strict";
import { test } from "node:test";
import { createItaniumRecords, isSupportedTypeName } from
  "../../../../analyzers/itanium-rtti/records.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

for (const name of ["4Base", "N2ns4BaseE", "St9type_info", "NSt2ns4BaseE"]) {
  void test(`accepts supported encoding ${name}`, () => assert.equal(isSupportedTypeName(name), true));
}
for (const name of ["", "N", "NE", "St", "0", "04Base", "5Base", "1!", "4BasÃ©",
  "x4Base", "4!ase", "4Bas!", "14BaseE", "N14Base", "NE4BasE", "4Bas\u00e9",
  "4Base1X", "N4Base", "N4BaseEE", "999999999999999999999X", "3FooIiE"]) {
  void test(`rejects unsupported/malformed encoding ${name}`, () =>
    assert.equal(isSupportedTypeName(name), false));
}
void test("caches name and vtable reads", async () => {
  const fixture = createItaniumFixture();
  const records = createItaniumRecords(fixture.image);
  assert.equal(records.name(fixture.addresses.base), records.name(fixture.addresses.base));
  assert.equal(records.table(fixture.addresses.table), records.table(fixture.addresses.table));
  assert.equal(await records.name(fixture.addresses.base), "4Base");
  assert.deepEqual((await records.table(fixture.addresses.table))?.functionPrefix,
    [fixture.addresses.code, fixture.addresses.code + 16]);
});
for (const [label, edit] of Object.entries({
  missingName: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.pointers.delete(fixture.addresses.base + 8),
  nonAscii: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.bytes.fill(255, fixture.image.pointers.get(fixture.addresses.base + 8)!),
  whitespace: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.bytes.fill(32, fixture.image.pointers.get(fixture.addresses.base + 8)!),
  unterminated: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.bytes.fill(65, fixture.image.pointers.get(fixture.addresses.base + 8)!)
})) {
  void test(`rejects ${label}`, async () => {
    const fixture = createItaniumFixture();
    edit(fixture);
    assert.equal(await createItaniumRecords(fixture.image).name(fixture.addresses.base), null);
  });
}
for (const address of [-8, 0, 17, 4000]) {
  void test(`rejects invalid vtable at ${address}`, async () => {
    assert.equal(await createItaniumRecords(createItaniumFixture().image).table(address), null);
  });
}
void test("rejects unaligned or truncated type headers", async () => {
  const fixture = createItaniumFixture();
  fixture.image.pointers.set(4088 + 8, 1100);
  const records = createItaniumRecords(fixture.image);
  assert.equal(await records.name(17), null);
  assert.equal(await records.name(4088), null);
});
for (const [label, edit] of Object.entries({
  noType: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.pointers.delete(fixture.addresses.table - 8),
  noFirst: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.pointers.delete(fixture.addresses.table),
  noSecond: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.pointers.delete(fixture.addresses.table + 8),
  dataFirst: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.pointer(fixture.addresses.table, fixture.addresses.base),
  dataSecond: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.pointer(fixture.addresses.table + 8, fixture.addresses.base),
  secondary: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.word(fixture.addresses.table - 16, -8n),
  relocatedOffset: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.relocations.add(fixture.addresses.table - 16),
  truncated: (fixture: ReturnType<typeof createItaniumFixture>) => {
    fixture.image.read = async () => new DataView(new ArrayBuffer(0));
  }
})) {
  void test(`rejects vtable ${label}`, async () => {
    const fixture = createItaniumFixture();
    edit(fixture);
    assert.equal(await createItaniumRecords(fixture.image).table(fixture.addresses.table), null);
  });
}
