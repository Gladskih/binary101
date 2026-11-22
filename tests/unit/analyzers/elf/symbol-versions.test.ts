import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfSymbolVersions } from "../../../../analyzers/elf/symbol-versions.js";
import { elfVersionFixture } from "../../../fixtures/elf-versions.js";

void test("decodes version definitions, requirements and hidden indices", async () => {
  const fixture = elfVersionFixture();
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result, {
    definitions: [{ index: 2, flags: 0, hash: 0x1234, names: ["LIB_1"] }],
    requirements: [{ file: "libsample.so", versions: [
      { index: 3, flags: 0, hash: 0, name: "LIB_2" }
    ] }], symbols: [0, 0x8002], issues: []
  });
});

void test("decodes big endian version records", async () => {
  const fixture = elfVersionFixture("big");
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.equal(result?.definitions[0]?.names[0], "LIB_1");
  assert.equal(result?.requirements[0]?.versions[0]?.index, 3);
  assert.deepEqual(result?.issues, []);
});

void test("warns on truncated version data without throwing", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[3]!.size = 19n;
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result?.definitions, []);
  assert.match(result!.issues.join(" "), /truncated/);
});

void test("rejects overlapping version auxiliary records", async () => {
  const fixture = elfVersionFixture();
  fixture.view.setUint32(76, 1, true);
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.match(result!.issues.join(" "), /auxiliary/);
});

void test("returns null when no version metadata exists", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections = [];
  assert.equal(await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 0), null);
});

void test("reports extra version indices against the linked dynamic symbol table", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[5]!.size = 6n;

  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 3);

  assert.deepEqual(result?.symbols, [0, 0x8002]);
  assert.match(result!.issues.join(" "), /3 entries.*2 dynamic symbols/);
});

void test("does not infer a count mismatch from an unavailable linked dynamic symbol section", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[5]!.link = 1; // Links to SHT_STRTAB instead of the dynsym.
  fixture.elf.sections[5]!.size = 6n;

  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 3);

  assert.deepEqual(result?.symbols, [0, 0x8002, 0]);
  assert.deepEqual(result?.issues, []);
});

void test("does not interpret a compressed version section as plain version records", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[5]!.flags = 0x800n; // SHF_COMPRESSED, gABI 3.7.

  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);

  assert.deepEqual(result?.symbols, []);
  assert.deepEqual(result?.issues, ["symbols: compressed version section cannot be read as a version table."]);
});

void test("reports a missing version index once for multiple symbols using it", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[2]!.size = 72n;
  fixture.elf.sections[5]!.size = 6n;
  fixture.view.setUint16(194, 4, true);
  fixture.view.setUint16(196, 0x8004, true);

  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 3);

  assert.deepEqual(result?.issues, ["Dynamic symbol #1 uses version index 4 absent from VERDEF or VERNEED."]);
});

void test("retains version indices before a partial last entry", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[5]!.size = 3n;

  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);

  assert.deepEqual(result?.symbols, [0]);
  assert.match(result!.issues.join(" "), /truncated.*decoded 1 of 2 entries/);
  assert.match(result!.issues.join(" "), /partial 2-byte entry/);
});

void test("withholds missing-version claims for an unreadable dynamic table", async () => {
  const fixture = elfVersionFixture();
  // PT_DYNAMIC exists, but has no readable dynamic table.
  fixture.elf.programHeaders.push({ type: 2, typeName: null, index: 0,
    offset: 0n, vaddr: 0n, paddr: 0n, filesz: 0n, memsz: 0n,
    flags: 0, flagNames: [], align: 1n });
  fixture.view.setUint16(194, 0x8004, true);

  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);

  assert.deepEqual(result?.symbols, [0, 0x8004]);
  assert.deepEqual(result?.issues, []);
});

for (const [index, size, diagnostic] of [
  [0x8003, 32n, null], [0x8004, 32n, /index 4.*VERDEF or VERNEED/],
  [0xffff, 32n, null], [0x8004, 20n, null]
] as const) {
  void test(`cross-checks version index ${index} with requirement size ${size}`, async () => {
    const fixture = elfVersionFixture();
    fixture.view.setUint16(194, index, true);
    fixture.elf.sections[4]!.size = size;

    const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);

    assert.equal(result?.symbols[1], index);
    const issues = result?.issues.filter(issue => issue.includes("VERDEF or VERNEED"));
    assert.deepEqual(issues?.map(issue => diagnostic?.test(issue)), diagnostic ? [true] : []);
  });
}
