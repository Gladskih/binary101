import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeItaniumRtti } from "../../../../analyzers/pe/itanium-rtti.js";
import { isPeWindowsParseResult, parsePe } from "../../../../analyzers/pe/index.js";
import { createPeItaniumFixture } from "../../../fixtures/pe-itanium-rtti.js";

for (const width of [4, 8] as const) {
  void test(`detects PE${width * 8} with relocation evidence`, async () => {
    const fixture = createPeItaniumFixture(width);
    const result = await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations);
    assert.equal(result?.types.find(type => type.name === "4Base")?.address,
      fixture.resultAddress(fixture.addresses.base));
    assert.deepEqual(Object.keys(result!).sort(), ["types", "warnings"]);
  });
}
void test("exposes RTTI through the full PE parser", async () => {
  const parsed = await parsePe(createPeItaniumFixture().reader());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.itaniumRtti?.types.some(type => type.name === "8Multiple"));
});
type Fixture = ReturnType<typeof createPeItaniumFixture>;
const addUnmappedBlock = (fixture: Fixture): typeof fixture.relocations.blocks[number] => {
  const block = { pageRva: 0x6000, size: 12, count: 2,
    entries: [{ type: 10, offset: 0 }, { type: 0, offset: 0 }] };
  fixture.relocations.blocks.push(block);
  fixture.relocations.totalEntries += 2;
  return block;
};
for (const [label, edit] of Object.entries({
  machine: (fixture: Fixture) => { fixture.core.coff.Machine = 0xaa64; },
  magic: (fixture: Fixture) => { fixture.core.opt.Magic = 0x10b; },
  stripped: (fixture: Fixture) => { fixture.core.coff.Characteristics = 1; },
  warnings: (fixture: Fixture) => { fixture.relocations.warnings = ["truncated"]; },
  count: (fixture: Fixture) => { fixture.relocations.totalEntries++; },
  page: (fixture: Fixture) => { fixture.relocations.blocks[0]!.pageRva++; },
  negativePage: (fixture: Fixture) => { fixture.relocations.blocks[0]!.pageRva = -4096; },
  overflowPage: (fixture: Fixture) => { fixture.relocations.blocks[0]!.pageRva = 0x100000000; },
  nanPage: (fixture: Fixture) => { fixture.relocations.blocks[0]!.pageRva = NaN; },
  size: (fixture: Fixture) => { fixture.relocations.blocks[0]!.size += 4; },
  alignment: (fixture: Fixture) => { fixture.relocations.blocks[0]!.size++; },
  blockCount: (fixture: Fixture) => { fixture.relocations.blocks[0]!.count++; },
  offset: (fixture: Fixture) => { fixture.relocations.blocks[0]!.entries[0]!.offset = 4096; },
  negativeOffset: (fixture: Fixture) => { fixture.relocations.blocks[0]!.entries[0]!.offset = -1; },
  fractionalOffset: (fixture: Fixture) => { fixture.relocations.blocks[0]!.entries[0]!.offset = 0.5; },
  type: (fixture: Fixture) => { fixture.relocations.blocks[0]!.entries[0]!.type = 3; },
  duplicate: (fixture: Fixture) => {
    fixture.relocations.blocks[0]!.entries[1] = { ...fixture.relocations.blocks[0]!.entries[0]! };
  },
  overlap: (fixture: Fixture) => {
    fixture.relocations.blocks[0]!.entries[1]!.offset =
      fixture.relocations.blocks[0]!.entries[0]!.offset + 1;
  },
  empty: (fixture: Fixture) => { fixture.relocations.blocks = []; fixture.relocations.totalEntries = 0; },
  image: (fixture: Fixture) => { fixture.core.opt.SizeOfImage = 0; },
  noData: (fixture: Fixture) => { fixture.core.sections[1]!.characteristics = 0; }
})) {
  void test(`silently rejects untrustworthy PE evidence: ${label}`, async () => {
    const fixture = createPeItaniumFixture();
    edit(fixture);
    assert.equal(await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations), null);
  });
}
void test("requires relocations", async () => {
  const fixture = createPeItaniumFixture();
  assert.equal(await analyzePeItaniumRtti(fixture.reader(), fixture.core, null), null);
});
void test("reports resource limit separately from rejected candidates", async () => {
  const fixture = createPeItaniumFixture();
  fixture.relocations.totalEntries = 250001;
  const result = await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations);
  assert.deepEqual(result?.types, []);
  assert.match(result?.warnings.join() ?? "", /limit/);
});
void test("reports I/O failure", async () => {
  const fixture = createPeItaniumFixture();
  const reader = fixture.reader();
  reader.read = async () => { throw new Error("unavailable"); };
  const result = await analyzePeItaniumRtti(reader, fixture.core, fixture.relocations);
  assert.match(result?.warnings.join() ?? "", /could not read/);
});
for (const value of [0n, 0xffffffffffffffffn]) {
  void test(`does not wrap a VA outside the image: ${value}`, async () => {
    const fixture = createPeItaniumFixture();
    fixture.view.setBigUint64(0x400 + fixture.addresses.base, value, true);
    const result = await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations);
    assert.ok(result);
    assert.equal(result.types.some(type => type.name === "4Base"), false);
  });
}

for (const [label, edit] of Object.entries({
  negativePage: (block: ReturnType<typeof addUnmappedBlock>) => { block.pageRva = -4096; },
  overflowPage: (block: ReturnType<typeof addUnmappedBlock>) => { block.pageRva = 0x100000000; },
  nanPage: (block: ReturnType<typeof addUnmappedBlock>) => { block.pageRva = NaN; },
  unalignedPage: (block: ReturnType<typeof addUnmappedBlock>) => { block.pageRva++; },
  unalignedSize: (block: ReturnType<typeof addUnmappedBlock>) => { block.size++; },
  wrongSize: (block: ReturnType<typeof addUnmappedBlock>) => { block.size += 4; },
  wrongCount: (block: ReturnType<typeof addUnmappedBlock>) => { block.count++; },
  negativeOffset: (block: ReturnType<typeof addUnmappedBlock>) => { block.entries[0]!.offset = -1; },
  excessiveOffset: (block: ReturnType<typeof addUnmappedBlock>) => { block.entries[0]!.offset = 4096; },
  fractionalOffset: (block: ReturnType<typeof addUnmappedBlock>) => { block.entries[0]!.offset = 0.5; }
})) {
  void test(`rejects ${label} even outside the otherwise valid RTTI graph`, async () => {
    const fixture = createPeItaniumFixture();
    edit(addUnmappedBlock(fixture));
    assert.equal(await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations), null);
  });
}
for (const displacement of [0, 1]) {
  void test(`rejects extra overlapping fixup (${displacement}) without losing graph pointers`, async () => {
    const fixture = createPeItaniumFixture();
    const block = addUnmappedBlock(fixture);
    block.pageRva = 0x2000;
    block.entries[0]!.offset = fixture.relocations.blocks[0]!.entries[0]!.offset + displacement;
    assert.equal(await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations), null);
  });
}
void test("accepts unordered relocations and irrelevant fixups without changing findings", async () => {
  const fixture = createPeItaniumFixture();
  const expected = await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations);
  const block = addUnmappedBlock(fixture);
  block.pageRva = 0;
  fixture.relocations.blocks[0]!.entries.reverse();
  assert.deepEqual(await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations), expected);
});
