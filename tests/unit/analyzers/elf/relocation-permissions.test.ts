import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfRelocations } from "../../../../analyzers/elf/relocations.js";
import { createElfRelocationPermissionCheck } from "../../../../analyzers/elf/relocation-permissions.js";
import { selectElfBinaryLayout } from "../../../../analyzers/elf/binary-layout.js";
import type { ElfRelocationTable } from "../../../../analyzers/elf/relocation-types.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationStorage } from "../../../fixtures/elf-relocations.js";

// gABI 7.4 and 8.3: PF_W=2, DT_TEXTREL=22, DT_FLAGS=30 and DF_TEXTREL=4.
for (const [bits, machine, code, flags, textrel, warning] of [
  [64, 62, 8n, 5, [], true], [32, 3, 8n, 4, [], true], [64, 183, 1027n, 4, [[30, 0n]], true],
  [64, 62, 8n, 6, [], false], [64, 62, 8n, 5, [[22, 0n]], false],
  [64, 62, 8n, 5, [[30, 4n]], false], [64, 62, 0n, 5, [], false]
] as const) {
  void test(`checks dynamic relocation machine=${machine}, type=${code}, flags=${flags}, TEXTREL tags=${textrel.length}`,
    async () => {
      const fixture = dynamicRelocationFixture(bits);
      fixture.elf.header.machine = machine;
      fixture.elf.programHeaders[0]!.flags = flags;
      const target = relocationStorage.loadAddress + BigInt(relocationStorage.target);
      fixture.word(relocationStorage.records, target);
      fixture.word(relocationStorage.records + bits / 8, code);
      textrel.forEach(([tag, value]) => fixture.tags.set(tag, value));
      fixture.installTags();

      const result = await parseElfRelocations(fixture.file(), fixture.elf);

      assert.deepEqual(result?.issues.filter(issue => issue.includes("without DT_TEXTREL")), warning ? [
        `Dynamic relocation at 0x${target.toString(16)} writes to a non-writable PT_LOAD without DT_TEXTREL or DF_TEXTREL.`
      ] : []);
    });
}

const permissionFixture = () => {
  const fixture = dynamicRelocationFixture();
  fixture.installTags();
  const load = fixture.elf.programHeaders[0]!;
  load.flags = 4;
  const issues: string[] = [];
  const read = () => createElfRelocationPermissionCheck(fixture.elf,
    { entries: [], terminated: true }, selectElfBinaryLayout(fixture.elf), issues);
  const table: ElfRelocationTable = { encoding: "RELA", sources: [".rela.dyn", "DT_RELA"],
    offset: 0, size: 24, entrySize: 24, sectionIndex: null, targetSectionIndex: null, symbolTableIndex: null };
  return { fixture, table, issues, read, target: load.vaddr + BigInt(relocationStorage.target) };
};

for (const [type, dynamic, supported] of [[1, true, false], [2, true, true], [3, true, true], [3, false, false]]) {
  void test(`scopes runtime permission validation to image type=${type}, PT_DYNAMIC=${dynamic}`, () => {
    const { fixture, read } = permissionFixture();
    fixture.elf.header.type = Number(type);
    if (!dynamic) fixture.elf.programHeaders.pop();

    assert.equal(Boolean(read()), supported);
  });
}

for (const encoding of ["RELR", "AUTH_RELR", "RELA"] as const) {
  void test(`only ${encoding} records with a known write width can prove missing TEXTREL`, () => {
    const { fixture, table, read, issues, target } = permissionFixture();
    // Writable non-load headers are not mappings and cannot cover the write.
    fixture.elf.programHeaders.push({ ...fixture.elf.programHeaders[0]!, type: 4, flags: 6 });
    read()?.({ ...table, encoding }, target, undefined);

    assert.equal(issues.length, encoding === "RELA" ? 0 : 1);
  });
}

void test("skips section-only relocations and reports the first confirmed runtime write once", () => {
  const { table, read, issues, target } = permissionFixture();
  const check = read()!;
  check({ ...table, sources: [".rela.dyn"] }, target, 8n);
  assert.deepEqual(issues, []);

  check(table, target, 8n);
  check(table, target + 8n, 8n);

  assert.deepEqual(issues, [
    `Dynamic relocation at 0x${target.toString(16)} writes to a non-writable PT_LOAD without DT_TEXTREL or DF_TEXTREL.`
  ]);
});

void test("relocation permissions remain uncertain while DT_NULL has not been seen", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.programHeaders[0]!.flags = 4;
  fixture.word(relocationStorage.records, relocationStorage.loadAddress + BigInt(relocationStorage.target));
  fixture.word(relocationStorage.records + 8, 8n); // R_X86_64_RELATIVE.
  fixture.installTags();
  fixture.elf.programHeaders[1]!.filesz -= 16n; // Exclude the final Elf64_Dyn (DT_NULL).

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.match(result!.issues.join(" "), /missing DT_NULL/);
  assert.doesNotMatch(result!.issues.join(" "), /without DT_TEXTREL/);
});

void test("reports bounds failure without also calling an unmapped write a text relocation", async () => {
  const fixture = dynamicRelocationFixture();
  const load = fixture.elf.programHeaders[0]!;
  load.flags = 4;
  fixture.word(relocationStorage.records, load.vaddr + load.memsz - 1n);
  fixture.word(relocationStorage.records + 8, 8n); // R_X86_64_RELATIVE writes an eight-byte word.
  fixture.installTags();

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.match(result!.issues.join(" "), /outside PT_LOAD memory/);
  assert.doesNotMatch(result!.issues.join(" "), /without DT_TEXTREL/);
});

for (const [length, warning] of [[4n, true], [8n, false]] as const) {
  void test(`checks ${length} writable bytes of a word crossing PT_LOAD ranges`, async () => {
    const fixture = dynamicRelocationFixture();
    const load = fixture.elf.programHeaders[0]!;
    const target = load.vaddr + BigInt(relocationStorage.target);
    // Two adjacent writable segments cover a relative write only when both have four bytes.
    fixture.elf.programHeaders.push({ ...load, index: 2, vaddr: target, filesz: 4n, memsz: 4n });
    if (length === 8n) {
      fixture.elf.programHeaders.push({ ...load, index: 3, vaddr: target + 4n, filesz: 4n, memsz: 4n });
    }
    load.flags = 4;
    fixture.word(relocationStorage.records, target);
    fixture.word(relocationStorage.records + 8, 8n); // R_X86_64_RELATIVE.
    fixture.installTags();

    const result = await parseElfRelocations(fixture.file(), fixture.elf);

    assert.equal(result?.issues.some(issue => issue.includes("without DT_TEXTREL")), warning);
  });
}
