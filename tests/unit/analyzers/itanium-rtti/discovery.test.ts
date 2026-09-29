import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture, createRttiOnlyFixture, setOrdinaryItaniumSlots } from
  "../../../fixtures/itanium-rtti.js";

for (const width of [4, 8] as const) {
  void test(`reserves ${width}-byte RTTI without a user vtable but does not publish orphan types`, async () => {
    const fixture = createRttiOnlyFixture(width);
    fixture.image.readOrder = address => fixture.bytes.length - address;

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.vtables.some(table => table.address === fixture.falseAddressPoint), false);
    assert.equal(result.types.some(type => ["8RttiOnly", "6EmptyA", "6EmptyB"].includes(type.name)), false);
    assert.deepEqual(result.warnings, []);
  });
}

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
  void test(`does not reserve unvalidated standalone RTTI bytes (${label})`, async () => {
    const fixture = createRttiOnlyFixture(8);
    edit(fixture);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    // These bytes meet the vtable predicate; only fully validated metadata may exclude them.
    assert.ok(result.vtables.some(table => table.address === fixture.falseAddressPoint));
    assert.equal(result.types.some(type => type.name === "8RttiOnly"), false);
    assert.deepEqual(result.warnings, []);
  });
}

for (const width of [4, 8] as const) {
  for (const slots of ["one function", "first null"] as const) {
    void test(`recognizes ${width}-byte ordinary vtable with ${slots}`, async () => {
      const fixture = createItaniumFixture(width);
      const { table, base } = fixture.addresses;
      setOrdinaryItaniumSlots(fixture, slots);

      const result = await discoverItaniumRtti(fixture.image);

      assert.deepEqual(result?.vtables.find(row => row.address === table), {
        address: table, typeAddress: base, offsetToTop: 0
      });
      assert.deepEqual(result?.warnings, []);
    });
  }
  void test(`rejects ${width}-byte ordinary vtable with first data pointer`, async () => {
    const fixture = createItaniumFixture(width);
    setOrdinaryItaniumSlots(fixture, "first data");

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.vtables.some(row => row.address === fixture.addresses.table), false);
  });
  for (const secondOffsetFlags of [0n, 2050n]) {
    void test(`omits vtable inside ${width}-byte VMI base array (${secondOffsetFlags})`, async () => {
      const fixture = createItaniumFixture(width);
      const { multiple, classTable, vmiObjectTable } = fixture.addresses;
      // ABI 2.9.5: two base descriptors, each {type_info*, offset_flags}.
      // 0 = private nonvirtual base at offset 0; 2050 = public base at offset 8.
      const array = multiple + 2 * width + 8;
      fixture.type(1024, classTable, "6EmptyA");
      fixture.type(1056, classTable, "6EmptyB");
      fixture.view.setUint32(multiple + 2 * width + 4, 2, true);
      fixture.pointer(array, 1024);
      fixture.word(array + width, 0n);
      fixture.pointer(array + 2 * width, 1056);
      fixture.word(array + 3 * width, secondOffsetFlags);
      // File order can differ from RVA order; the overlap sweep must sort independently.
      fixture.image.readOrder = address => fixture.bytes.length - address;

      const result = await discoverItaniumRtti(fixture.image);

      assert.ok(result);
      assert.ok(result.vtables.some(row => row.address === vmiObjectTable));
      assert.deepEqual(result.types.find(row => row.address === multiple)?.bases, [
        { typeAddress: 1024, offset: 0, isVirtual: false, isPublic: false },
        { typeAddress: 1056, offset: Number(secondOffsetFlags >> 8n),
          isVirtual: false, isPublic: secondOffsetFlags !== 0n }
      ]);
      assert.equal(result.vtables.some(row => row.address === array + 3 * width), false);
      assert.deepEqual(result.warnings, []);
    });
  }
}

type Fixture = ReturnType<typeof createItaniumFixture>;
void test("rejects a header that overlaps only the final VMI offset field", async () => {
  const fixture = createItaniumFixture();
  const { multiple, base, vmiObjectTable } = fixture.addresses;
  // A one-base x64 VMI object occupies 40 bytes; its last offset_flags is at +32.
  fixture.word(multiple + 32, 0n);
  fixture.pointer(multiple + 40, base);

  const result = await discoverItaniumRtti(fixture.image);

  assert.ok(result?.vtables.some(table => table.address === vmiObjectTable));
  assert.equal(result?.vtables.some(table => table.address === multiple + 48), false);
});

for (const [kind, key, size] of [
  ["class", "base", 16], ["si", "derived", 24], ["vmi", "multiple", 40]
] as const) {
  for (const side of ["before", "after"] as const) {
    void test(`accepts a null first slot adjacent to ${kind} RTTI (${side})`, async () => {
      const fixture = createItaniumFixture();
      // x64 ABI records: 2 pointers, 3 pointers, or 2 pointers + flags/count + one base.
      const address = fixture.addresses[key] + (side === "before" ? -8 : size + 16);
      fixture.pointer(address - 8, fixture.addresses.base);

      const result = await discoverItaniumRtti(fixture.image);

      assert.ok(result?.vtables.some(table => table.address === address));
    });
  }
}

for (const [corruption, edit] of Object.entries({
  unknownRuntime: (fixture: Fixture) => fixture.pointer(fixture.addresses.base, fixture.addresses.table),
  malformedName: (fixture: Fixture) => fixture.type(fixture.addresses.base, fixture.addresses.classTable, "0"),
  secondary: (fixture: Fixture) => fixture.word(fixture.addresses.table - 16, -8n),
  offsetRelocation: (fixture: Fixture) => fixture.image.relocations.add(fixture.addresses.table - 16),
  missingTypeRelocation: (fixture: Fixture) => fixture.image.relocations.delete(fixture.addresses.table - 8)
})) {
  void test(`rejects ordinary vtable with ${corruption}`, async () => {
    const fixture = createItaniumFixture();
    edit(fixture);

    const result = await discoverItaniumRtti(fixture.image);

    assert.ok(result);
    assert.equal(result.vtables.some(row => row.address === fixture.addresses.table), false);
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
    assert.ok(result?.vtables.some(row => row.address === fixture.addresses.table));
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

void test("does not publish orphan bases of an invalid graph", async () => {
  const fixture = createItaniumFixture();
  fixture.type(1024, fixture.addresses.classTable, "6Orphan");
  fixture.view.setUint32(fixture.addresses.multiple + 20, 2, true);
  fixture.pointer(fixture.addresses.multiple + 24, 1024);
  fixture.pointer(fixture.addresses.multiple + 40, 1080);
  const result = await discoverItaniumRtti(fixture.image);
  assert.ok(result);
  assert.equal(result.types.some(type => type.name === "6Orphan"), false);
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
  assert.equal(result.types.some(type => type.name === "4Deep"), false);
  assert.match(result.warnings.join(), /depth limit/);
  assert.deepEqual(result.vtables, []);
});

void test("requires a file-backed virtual base offset slot in the referencing vtable", async () => {
  const fixture = createItaniumFixture();
  fixture.word(fixture.addresses.multiple + 32, -0x100000n + 3n);
  const result = await discoverItaniumRtti(fixture.image);
  assert.ok(result);
  assert.equal(result.vtables.some(table => table.address === fixture.addresses.vmiObjectTable), false);
  assert.equal(result.types.some(type => type.name === "8Multiple"), false);
});

for (const scenario of ["relocated", "negative", "truncated"] as const) {
  void test(`rejects a ${scenario} virtual base slot`, async () => {
    const fixture = createItaniumFixture();
    const slot = fixture.addresses.vmiObjectTable - 24;
    const edits = {
      relocated: () => fixture.image.relocations.add(slot),
      negative: () => fixture.word(slot, -1n),
      truncated: () => {
        const read = fixture.image.read;
        fixture.image.read = (address, size) => read(address, address === slot ? 0 : size);
      }
    };
    edits[scenario]();
    const result = await discoverItaniumRtti(fixture.image);
    assert.ok(result);
    assert.equal(result.vtables.some(table => table.address === fixture.addresses.vmiObjectTable), false);
    assert.deepEqual(result.warnings, []);
  });
}
