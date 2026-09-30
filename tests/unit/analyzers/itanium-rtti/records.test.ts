import assert from "node:assert/strict";
import { test } from "node:test";
import { createItaniumRecords, isSupportedTypeName } from
  "../../../../analyzers/itanium-rtti/records.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

for (const name of ["4Base", "N2ns4BaseE", "St9type_info", "NSt2ns4BaseE"]) {
  void test(`accepts supported encoding ${name}`, () => assert.equal(isSupportedTypeName(name), true));
}
for (const name of ["3FooIiE", "0", "with spaces", "\u00ff"]) {
  void test(`reads structurally backed NTBS independently of supported grammar (${name})`, async () => {
    const fixture = createItaniumFixture();
    const target = fixture.image.pointers.get(fixture.addresses.base + 8)!;
    fixture.bytes.set([...name].map(character => character.charCodeAt(0)).concat(0), target);

    const result = await createItaniumRecords(fixture.image).name(fixture.addresses.base);

    assert.equal(result, name);
    assert.equal(isSupportedTypeName(result!), false);
  });
}
void test("rejects an empty structurally backed name", async () => {
  const fixture = createItaniumFixture();
  fixture.type(fixture.addresses.base, fixture.addresses.classTable, "");
  assert.equal(await createItaniumRecords(fixture.image).name(fixture.addresses.base), null);
});
for (const name of ["", "N", "NE", "St", "0", "04Base", "5Base", "1!", "4BasÃ©",
  "x4Base", "4!ase", "4Bas!", "14BaseE", "N14Base", "NE4BasE", "4Bas\u00e9",
  "4Base1X", "N4Base", "N4BaseEE", "999999999999999999999X", "3FooIiE"]) {
  void test(`rejects unsupported/malformed encoding ${name}`, () =>
    assert.equal(isSupportedTypeName(name), false));
}
void test("caches name and runtime vtable reads", async () => {
  const fixture = createItaniumFixture();
  const records = createItaniumRecords(fixture.image);
  assert.equal(records.name(fixture.addresses.base), records.name(fixture.addresses.base));
  assert.equal(records.runtimeTable(fixture.addresses.table), records.runtimeTable(fixture.addresses.table));
  assert.equal(records.runtimeTable(fixture.addresses.classTable),
    records.runtimeTable(fixture.addresses.classTable));
  assert.equal(await records.name(fixture.addresses.base), "4Base");
  assert.deepEqual(await records.runtimeTable(fixture.addresses.table), {
    typeAddress: fixture.addresses.base
  });
});

void test("prepares standalone type names once, including failed and duplicate candidates", async () => {
  const fixture = createItaniumFixture();
  const read = fixture.image.read;
  let reads = 0;
  fixture.image.read = (address, size) => { reads++; return read(address, size); };
  const records = createItaniumRecords(fixture.image);
  const addresses = [fixture.addresses.base, fixture.addresses.base, 4088];
  await records.prepareTypes(addresses);
  assert.equal(await records.name(fixture.addresses.base), "4Base");
  assert.equal(await records.name(4088), null);
  const before = reads;

  await records.prepareTypes(addresses);

  assert.equal(reads, before);
});

for (const available of [16, 17, 23, 24, 31, 32]) {
  void test(`requires both complete bootstrap slots (${available} bytes available)`, async () => {
    const fixture = createItaniumFixture();
    const read = fixture.image.read;
    fixture.image.read = (address, size) => read(address,
      address === fixture.addresses.table - 16 ? Math.min(size, available) : size);

    const result = await createItaniumRecords(fixture.image).runtimeTable(fixture.addresses.table);

    assert.equal(result != null, available === 32);
  });
}

type Fixture = ReturnType<typeof createItaniumFixture>;
for (const width of [4, 8] as const) {
  for (const corruption of ["null", "missing relocation"] as const) {
    void test(`rejects ${width}-byte bootstrap second slot with ${corruption}`, async () => {
      const fixture = createItaniumFixture(width);
      const site = fixture.addresses.classTable + width;
      const edits = {
        null: () => fixture.word(site, 0n),
        "missing relocation": () => fixture.image.relocations.delete(site)
      };
      edits[corruption]();

      assert.equal(await createItaniumRecords(fixture.image).runtimeTable(fixture.addresses.classTable), null);
    });
  }
  for (const [label, edit] of Object.entries({
    dataPointer: (fixture: Fixture) => fixture.pointer(fixture.addresses.table, fixture.addresses.base),
    scalar: (fixture: Fixture) => {
      fixture.image.pointers.delete(fixture.addresses.table);
      fixture.word(fixture.addresses.table, 1n);
    },
    relocatedNull: (fixture: Fixture) => fixture.word(fixture.addresses.table, 0n),
    indexedNull: (fixture: Fixture) => {
      fixture.pointer(fixture.addresses.table, fixture.addresses.code);
      fixture.word(fixture.addresses.table, 0n);
    },
    unindexedRelocation: (fixture: Fixture) => {
      fixture.image.pointers.delete(fixture.addresses.table);
      fixture.word(fixture.addresses.table, BigInt(fixture.addresses.code));
      fixture.image.relocations.add(fixture.addresses.table);
    },
    missingRelocation: (fixture: Fixture) => {
      fixture.pointer(fixture.addresses.table, fixture.addresses.code);
      fixture.image.relocations.delete(fixture.addresses.table);
    }
  })) {
    void test(`rejects ${width}-byte bootstrap slot with ${label}`, async () => {
      const fixture = createItaniumFixture(width);
      edit(fixture);

      assert.equal(await createItaniumRecords(fixture.image).runtimeTable(fixture.addresses.table), null);
    });
  }
}

void test("rejects truncated bootstrap function slots even with indexed pointers", async () => {
  const fixture = createItaniumFixture();
  const read = fixture.image.read;
  fixture.image.read = (address, size) => read(address,
    address === fixture.addresses.classTable - 16 ? 24 : size);

  assert.equal(await createItaniumRecords(fixture.image).runtimeTable(fixture.addresses.classTable), null);
});
for (const [label, edit] of Object.entries({
  missingName: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.pointers.delete(fixture.addresses.base + 8),
  unrelocatedName: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.relocations.delete(fixture.addresses.base + 8),
  unterminatedNonAscii: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.bytes.fill(255, fixture.image.pointers.get(fixture.addresses.base + 8)!),
  unterminatedWhitespace: (fixture: ReturnType<typeof createItaniumFixture>) =>
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
    assert.equal(await createItaniumRecords(createItaniumFixture().image).runtimeTable(address), null);
  });
}
void test("rejects unaligned or truncated type headers", async () => {
  const fixture = createItaniumFixture();
  fixture.image.pointers.set(4088 + 8, 1100);
  fixture.image.relocations.add(4088 + 8);
  const records = createItaniumRecords(fixture.image);
  assert.equal(await records.name(17), null);
  assert.equal(await records.name(4088), null);
});
for (const [label, edit] of Object.entries({
  noType: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.pointers.delete(fixture.addresses.table - 8),
  noTypeRelocation: (fixture: ReturnType<typeof createItaniumFixture>) =>
    fixture.image.relocations.delete(fixture.addresses.table - 8),
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
    assert.equal(await createItaniumRecords(fixture.image).runtimeTable(fixture.addresses.table), null);
  });
}
