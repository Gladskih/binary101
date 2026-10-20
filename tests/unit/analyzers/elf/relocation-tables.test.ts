import assert from "node:assert/strict";
import { test } from "node:test";
import { collectElfRelocationTables } from "../../../../analyzers/elf/relocation-tables.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

void test("ELF32 dynamic RELA uses the 12-byte ABI entry size", () => {
  const fixture = dynamicRelocationFixture(32);
  const issues: string[] = [];

  const tables = collectElfRelocationTables(fixture.elf, fixture.tags, issues);

  // Three Elf32_Word-sized fields: https://gabi.xinuos.com/elf/06-reloc.html
  assert.equal(tables[0]?.entrySize, 12);
  assert.equal(tables[0]?.size, 12);
  assert.deepEqual(issues, []);
});

void test("collects REL, RELA, RELR and both PLT encodings from dynamic tags", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(17, 0x1080n).set(18, 16n).set(19, 16n);
  fixture.tags.set(36, 0x10a0n).set(35, 8n).set(37, 8n);
  fixture.tags.set(23, 0x10b0n).set(2, 24n).set(20, 7n);
  const issues: string[] = [];

  const tables = collectElfRelocationTables(fixture.elf, fixture.tags, issues);
  fixture.tags.set(20, 17n).set(2, 16n);
  const relPlt = collectElfRelocationTables(fixture.elf, fixture.tags, issues);

  assert.deepEqual(tables.map(table => table.encoding), ["REL", "RELA", "RELR", "RELA"]);
  assert.equal(tables[3]?.sources[0], "DT_JMPREL");
  assert.equal(relPlt[3]?.entrySize, 16);
  assert.equal(relPlt[3]?.encoding, "REL");
  assert.deepEqual(issues, []);
});

void test("merges section and dynamic aliases, retaining provenance", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections.push(relocationSection(4, {
    name: ".rela.dyn", type: 4, offset: 64n, size: 24n, entsize: 24n, link: 2
  }));

  const tables = collectElfRelocationTables(fixture.elf, fixture.tags, []);

  assert.equal(tables.length, 1);
  assert.deepEqual(tables[0]?.sources, [".rela.dyn", "DT_RELA"]);
  assert.equal(tables[0]?.symbolTableIndex, 2);
});

for (const fields of [
  { offset: -1n }, { offset: 1025n }, { size: -1n }, { entsize: 0n },
  { entsize: 23n }, { offset: 1n << 63n }
]) {
  void test(`rejects invalid relocation section ${JSON.stringify(fields, (_, value: unknown) =>
    typeof value === "bigint" ? value.toString() : value)}`, () => {
    const fixture = dynamicRelocationFixture();
    fixture.elf.sections.push(relocationSection(4, {
      type: 4, offset: 64n, size: 24n, entsize: 24n, ...fields
    }));
    const issues: string[] = [];

    assert.deepEqual(collectElfRelocationTables(fixture.elf, new Map(), issues), []);
    assert.match(issues.join(" "), /invalid/);
  });
}

void test("partial entries warn; zero-sized tables do not invent entries", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(8, 25n);
  fixture.elf.sections.push(relocationSection(4, { type: 4 }));
  const issues: string[] = [];

  assert.equal(collectElfRelocationTables(fixture.elf, fixture.tags, issues)[0]?.size, 24);
  fixture.tags.set(8, 0n);
  assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, []), []);
  assert.match(issues.join(" "), /partial/);
});

for (const [tag, value] of [[7, 0x13f8n], [8, 1024n], [9, 0n], [7, -1n]] as const) {
  void test(`rejects invalid dynamic range/stride ${tag}=${value}`, () => {
    const fixture = dynamicRelocationFixture();
    fixture.tags.set(tag, value);
    const issues: string[] = [];

    assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, issues), []);
    assert.match(issues.join(" "), /invalid/);
  });
}

void test("requires address, size, stride and PLT encoding", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.delete(7);
  fixture.tags.set(23, 0x1080n);
  const issues: string[] = [];

  assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, issues), []);
  assert.match(issues.join(" "), /DT_PLTREL/);
  fixture.tags.delete(8);
  fixture.tags.set(7, 0x1040n);
  assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, []), []);
});

void test("RELCOUNT and RELACOUNT validate relative-prefix lengths", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(0x6ffffff9, 2n); // glibc elf.h: DT_RELACOUNT.
  const issues: string[] = [];

  collectElfRelocationTables(fixture.elf, fixture.tags, issues);

  assert.match(issues.join(" "), /relative prefix/);
});

void test("section boundaries and partial records retain only complete records", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections.push(relocationSection(4, {
    type: 4, offset: 0n, size: 25n, entsize: 24n
  }));
  fixture.elf.sections.push(relocationSection(5, {
    type: 19, offset: 1000n, size: 24n, entsize: 8n
  }));
  const issues: string[] = [];

  const tables = collectElfRelocationTables(fixture.elf, new Map(), issues);

  assert.equal(tables[0]?.size, 24);
  assert.deepEqual(tables[0]?.sources, ["section #4"]);
  assert.equal(tables[1]?.symbolTableIndex, null);
  assert.equal(tables[1]?.size, 24);
  assert.equal(issues.length, 1);
});

void test("truncation at EOF preserves complete records and warns even on an exact stride", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections.push(relocationSection(4, {
    type: 4, offset: 1000n, size: 48n, entsize: 24n
  }));
  const issues: string[] = [];

  const tables = collectElfRelocationTables(fixture.elf, new Map(), issues);

  assert.equal(tables[0]?.size, 24);
  assert.match(issues.join(" "), /truncated/);
});

void test("dynamic-only REL and RELR preserve tag source names", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(17, 0x1080n).set(18, 16n).set(19, 16n);
  fixture.tags.set(36, 0x10a0n).set(35, 8n).set(37, 8n);

  assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, [])
    .map(table => table.sources), [["DT_REL"], ["DT_RELA"], ["DT_RELR"]]);
});

void test("collects Android APS2, legacy RELR and machine-specific authenticated RELR", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.header.machine = 183; // EM_AARCH64; processor section IDs are not global.
  fixture.tags.set(0x6000000f, 0x1080n).set(0x60000010, 11n);
  fixture.tags.set(0x60000011, 0x10a0n).set(0x60000012, 13n);
  fixture.tags.set(0x6fffe000, 0x10c0n).set(0x6fffe001, 8n).set(0x6fffe003, 8n);
  fixture.tags.set(0x70000012, 0x10e0n).set(0x70000011, 8n).set(0x70000013, 8n);
  const issues: string[] = [];
  assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, issues).map(table => table.encoding),
    ["RELA", "ANDROID_REL", "ANDROID_RELA", "RELR", "AUTH_RELR"]);
  assert.deepEqual(issues, []);
});

for (const [type, encoding] of [[0x60000001, "ANDROID_REL"], [0x60000002, "ANDROID_RELA"],
  [0x40000014, "CREL"], [0x6fffff00, "RELR"], [0x70000004, "AUTH_RELR"]] as const) {
  void test(`discovers section encoding ${encoding} by type instead of name`, () => {
    const fixture = dynamicRelocationFixture();
    fixture.elf.header.machine = 183;
    fixture.elf.sections.push(relocationSection(4, { type, offset: 64n,
      size: 8n, entsize: encoding.endsWith("RELR") ? 8n : 0n }));
    const issues: string[] = [];
    assert.equal(collectElfRelocationTables(fixture.elf, new Map(), issues)[0]?.encoding, encoding);
    assert.deepEqual(issues, []);
  });
}

void test("CREL PLT uses byte sizes; DT_CREL aliases retain the section boundary", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.clear();
  fixture.tags.set(0x40000026, 0x1040n).set(23, 0x1060n).set(2, 6n).set(20, 0x40000026n);
  fixture.elf.sections.push(relocationSection(4, { type: 0x40000014,
    offset: 64n, size: 6n, entsize: 1n, link: 2 }));
  const issues: string[] = [];
  const tables = collectElfRelocationTables(fixture.elf, fixture.tags, issues);
  assert.equal(tables[0]?.size, 6);
  assert.deepEqual(tables[0]?.sources, ["section #4", "DT_CREL"]);
  assert.equal(tables[1]?.encoding, "CREL");
  assert.equal(tables[1]?.size, 6);
  assert.deepEqual(issues, []);
});

void test("AArch64-specific tags/sections do not reinterpret another machine's processor namespace", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.clear();
  fixture.tags.set(0x70000012, 0x1040n).set(0x70000011, 8n).set(0x70000013, 8n);
  fixture.elf.sections.push(relocationSection(4, { type: 0x70000004,
    offset: 64n, size: 8n, entsize: 8n }));
  assert.deepEqual(collectElfRelocationTables(fixture.elf, fixture.tags, []), []);
});

void test("entry-size-only tags left by LLD do not invent an absent unpacked table", () => {
  const fixture = dynamicRelocationFixture();
  const issues: string[] = [];
  assert.deepEqual(collectElfRelocationTables(fixture.elf, new Map([[9, 24n]]), issues), []);
  assert.deepEqual(issues, []);
});
