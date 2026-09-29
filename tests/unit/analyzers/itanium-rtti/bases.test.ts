import assert from "node:assert/strict";
import { test } from "node:test";
import { readItaniumBases } from "../../../../analyzers/itanium-rtti/bases.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

void test("parses class and single inheritance bodies", async () => {
  const fixture = createItaniumFixture();
  assert.deepEqual(await readItaniumBases(fixture.image, fixture.addresses.base, "class"), { bases: [] });
  assert.deepEqual(await readItaniumBases(fixture.image, fixture.addresses.derived, "si"), {
    bases: [{ typeAddress: fixture.addresses.base, offset: 0, isVirtual: false, isPublic: true }]
  });
  fixture.image.pointers.delete(fixture.addresses.derived + 16);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.derived, "si"), null);
});
for (const width of [4, 8] as const) {
  void test(`reads non-public nonvirtual base and flags (${width})`, async () => {
    const fixture = createItaniumFixture(width);
    fixture.word(fixture.addresses.multiple + 3 * width + 8, 4096n);
    fixture.view.setUint32(fixture.addresses.multiple + 2 * width, 3, true);
    assert.deepEqual(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), {
      flags: 3, bases: [{ typeAddress: fixture.addresses.base,
        offset: 16, isVirtual: false, isPublic: false }]
    });
  });
  void test(`reads distinct multiple bases (${width})`, async () => {
    const fixture = createItaniumFixture(width);
    fixture.view.setUint32(fixture.addresses.multiple + 2 * width + 4, 2, true);
    fixture.pointer(fixture.addresses.multiple + 4 * width + 8, fixture.addresses.derived);
    fixture.word(fixture.addresses.multiple + 5 * width + 8, 2n);
    assert.deepEqual((await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"))?.bases,
      [{ typeAddress: fixture.addresses.base, offset: -3 * width, isVirtual: true, isPublic: true },
        { typeAddress: fixture.addresses.derived, offset: 0, isVirtual: false, isPublic: true }]);
  });
}
for (const encoded of [-256n, 4n, 255n, -1n, -4093n, 3n, 0x7fffffffffffff00n]) {
  void test(`rejects invalid offset flags ${encoded}`, async () => {
    const fixture = createItaniumFixture();
    fixture.word(fixture.addresses.multiple + 32, encoded);
    assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
  });
}
for (const count of [0, 257, 0xffffffff]) {
  void test(`rejects unsupported base count ${count}`, async () => {
    const fixture = createItaniumFixture();
    fixture.view.setUint32(fixture.addresses.multiple + 20, count, true);
    assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
  });
}
void test("rejects undefined hierarchy bits", async () => {
  const fixture = createItaniumFixture();
  fixture.view.setUint32(fixture.addresses.multiple + 16, 4, true);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
});
void test("rejects missing relocation and duplicate direct bases", async () => {
  const fixture = createItaniumFixture();
  fixture.view.setUint32(fixture.addresses.multiple + 20, 2, true);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
  fixture.pointer(fixture.addresses.multiple + 40, fixture.addresses.base);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
});
for (const size of [0, 24]) {
  void test(`rejects truncated VMI body (${size})`, async () => {
    const fixture = createItaniumFixture();
    const original = fixture.image.read;
    fixture.image.read = (address, _requested) => original(address,
      address === fixture.addresses.multiple ? size : 0);
    assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
  });
}
void test("rejects truncated SI and relocated VMI scalars", async () => {
  const fixture = createItaniumFixture();
  fixture.pointer(4080, fixture.addresses.siTable);
  fixture.image.pointers.set(4096, fixture.addresses.base);
  assert.equal(await readItaniumBases(fixture.image, 4080, "si"), null);
  fixture.image.relocations.add(fixture.addresses.multiple + 32);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
  fixture.image.relocations.add(fixture.addresses.multiple + 20);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
  fixture.image.relocations.add(fixture.addresses.multiple + 16);
  assert.equal(await readItaniumBases(fixture.image, fixture.addresses.multiple, "vmi"), null);
});
