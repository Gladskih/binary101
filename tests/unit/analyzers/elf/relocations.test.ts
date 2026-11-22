import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfRelocations } from "../../../../analyzers/elf/relocations.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";

// glibc elf/do-rel.h and x86-64 dl-machine.h: relative types 8 and 38.
for (const [machine, info, count, warning] of [
  [62, 8n, 1n, null], [62, 38n, 1n, null], [62, 37n, 1n, /non-relative/],
  [62, 37n, 0n, null],
  [183, 1027n, 1n, null], [183, 1n << 32n | 1027n, 1n, null],
  [183, 1032n, 1n, /non-relative/], [243, 3n, 1n, null]
] as const) {
  void test(`validates DT_RELACOUNT on machine ${machine}, r_info ${info}, count ${count}`, async () => {
    const fixture = dynamicRelocationFixture();
    fixture.elf.header.machine = machine;
    fixture.tags.set(0x6ffffff9, count); // glibc elf.h: DT_RELACOUNT.
    fixture.word(64, 0x1200n);
    fixture.word(72, info);
    fixture.installTags();

    const result = await parseElfRelocations(fixture.file(), fixture.elf);

    const issues = result?.issues.filter(issue => issue.includes("DT_RELACOUNT"));
    assert.deepEqual(issues?.map(issue => warning?.test(issue)), warning ? [true] : []);
    assert.equal(result?.entries.length, 1);
  });
}

for (const [count, expected] of [
  [1n, []], [2n, ["DT_RELACOUNT prefix entry #1 has non-relative relocation type 7."]], [3n, []]
] as const) {
  void test(`limits RELA prefix classification to ${count} declared records`, async () => {
    const fixture = dynamicRelocationFixture();
    fixture.tags.set(8, 48n).set(0x6ffffff9, count); // Two Elf64_Rela records, DT_RELACOUNT.
    fixture.word(64, 0x1200n);
    fixture.word(72, 8n); // R_X86_64_RELATIVE.
    fixture.word(88, 0x1208n);
    fixture.word(96, 7n); // R_X86_64_JUMP_SLOT.
    fixture.installTags();

    const result = await parseElfRelocations(fixture.file(), fixture.elf);

    assert.equal(result?.entries.length, 2);
    assert.deepEqual(result?.issues.filter(issue => issue.startsWith("DT_RELACOUNT")), expected);
  });
}

void test("checks the full write for common dynamic relocations at the PT_LOAD boundary", async () => {
  const fixture = dynamicRelocationFixture();
  // x86-64 ABI R_X86_64_RELATIVE writes eight bytes.
  fixture.word(64, 0x17f9n);
  fixture.word(72, 8n);
  fixture.installTags();

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries[0]?.target, null);
  assert.match(result!.issues.join(" "), /8-byte.*outside PT_LOAD/);
});

void test("reads an i386 RELATIVE addend from the original file bytes", async () => {
  const fixture = dynamicRelocationFixture(32);
  fixture.tags.clear();
  fixture.tags.set(17, 0x1040n).set(18, 8n).set(19, 8n); // DT_REL / DT_RELSZ / DT_RELENT.
  fixture.tags.set(0x6ffffffa, 1n); // glibc elf.h: DT_RELCOUNT.
  fixture.word(64, 0x1200n);
  fixture.word(68, 8n); // R_386_RELATIVE, symbol zero.
  fixture.word(512, 0xfedcba98n);
  fixture.installTags();

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries[0]?.addend, null);
  assert.equal(result?.entries[0]?.storedAddend, 0xfedcba98n);
  assert.deepEqual(result?.issues, []);
});

void test("reports a nonzero symbol index in i386 DT_RELCOUNT", async () => {
  const fixture = dynamicRelocationFixture(32);
  fixture.tags.clear();
  fixture.tags.set(17, 0x1040n).set(18, 8n).set(19, 8n).set(0x6ffffffa, 1n);
  fixture.word(64, 0x1200n);
  fixture.word(68, 1n << 8n | 8n); // ELF32_R_INFO: symbol #1, R_386_RELATIVE.
  fixture.installTags();

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.ok(result?.issues.includes("DT_RELCOUNT prefix entry #0 has a nonzero symbol index (1)."));
});
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

void test("RELA resolves a linked static symbol and section-relative target", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections.push(relocationSection(4, {
    type: 4, offset: 64n, size: 24n, entsize: 24n, link: 2, info: 1
  }));
  fixture.word(64, 8n);
  fixture.word(72, (1n << 32n) | 1n); // gABI ELF64_R_INFO; R_X86_64_64 = 1.
  fixture.word(80, -4n);

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries.length, 1);
  assert.equal(result?.entries[0]?.symbol?.name, "target");
  assert.equal(result?.entries[0]?.type, 1);
  assert.equal(result?.entries[0]?.addend, -4n);
  assert.deepEqual(result?.entries[0]?.target, {
    sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n
  });
  assert.deepEqual(result?.issues, []);
});

void test("big-endian ELF32 REL preserves implicit addends", async () => {
  const fixture = relocationFixture(32, "big");
  fixture.elf.sections.push(relocationSection(4, {
    type: 9, offset: 64n, size: 8n, entsize: 8n, link: 2, info: 1
  }));
  fixture.word(64, 4n);
  fixture.word(68, (1n << 8n) | 2n); // gABI ELF32_R_INFO; R_386_PC32 = 2.

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries[0]?.symbolIndex, 1);
  assert.equal(result?.entries[0]?.symbol?.value, 4n);
  assert.equal(result?.entries[0]?.addend, null);
  assert.equal(result?.entries[0]?.target?.fileOffset, 516n);
});

void test("RELR expands consecutive bitmap words without symbols", async () => {
  const fixture = relocationFixture();
  fixture.elf.header.type = 3;
  fixture.elf.sections.push(relocationSection(4, {
    type: 19, offset: 64n, size: 24n, entsize: 8n
  })); // gABI SHT_RELR = 19, 63 sites per ELF64 bitmap.
  fixture.word(64, 0x1000n);
  fixture.word(72, 0xbn);
  fixture.word(80, 3n);

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.deepEqual(result?.entries.map(entry => entry.offset), [0x1000n, 0x1008n, 0x1018n, 0x1200n]);
  assert.equal(result?.entries[0]?.symbolIndex, null);
  assert.equal(result?.entries[0]?.type, null);
});

void test("malformed tables warn while retaining complete records", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections.push(relocationSection(4, {
    type: 4, offset: 1000n, size: 48n, entsize: 24n, info: 1
  }));

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries.length, 1);
  assert.match(result!.issues.join(" "), /truncated/i);
});

void test("ELF with no relocations returns null", async () => {
  const fixture = relocationFixture();

  assert.equal(await parseElfRelocations(fixture.file(), fixture.elf), null);
});

void test("sectionless DT_JMPREL resolves a symbol and a GOT target", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.delete(7);
  fixture.tags.delete(8);
  fixture.tags.delete(9);
  fixture.tags.set(23, 0x1040n).set(2, 24n).set(20, 7n);
  fixture.installTags();
  fixture.elf.sections = [];
  fixture.word(64, 0x1200n);
  fixture.word(72, (1n << 32n) | 7n);
  fixture.word(80, 0n);

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries[0]?.symbol?.name, "target");
  assert.equal(result?.entries[0]?.target?.fileOffset, 512n);
  assert.deepEqual(result?.tables[0]?.sources, ["DT_JMPREL"]);
  assert.deepEqual(result?.issues, []);
});

void test("overlapping section/dynamic tables decode once, retaining composed records", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections.push(relocationSection(4, {
    type: 4, offset: 64n, size: 48n, entsize: 24n, link: 2
  }));
  fixture.tags.set(7, 0x1058n);
  fixture.installTags();
  fixture.word(64, 0x1200n);
  fixture.word(72, 8n);
  fixture.word(88, 0x1200n);
  fixture.word(96, 8n);

  const result = await parseElfRelocations(fixture.file(), fixture.elf);

  assert.equal(result?.entries.length, 2);
  assert.deepEqual(result?.entries.map(entry => entry.recordOffset), [64, 88]);
});

void test("APS2 aliases preserve repeated records while sharing linked symbols", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.bytes.set([65, 80, 83, 50, 2, 0, 2, 3, 0, 8], 64);
  fixture.tags.clear();
  fixture.tags.set(0x60000011, 0x1040n).set(0x60000012, 10n);
  fixture.installTags();
  fixture.elf.sections.push(relocationSection(4, { type: 0x60000002, offset: 64n,
    size: 10n, entsize: 1n, link: 2 }));
  const result = await parseElfRelocations(fixture.file(), fixture.elf);
  assert.equal(result?.tables.length, 1);
  assert.equal(result?.entries.length, 2); // Same address is meaningful, not an alias to discard.
  assert.deepEqual(result?.entries.map(entry => entry.addend), [0n, 0n]);
});

void test("NONE does not demand a target and overlapping section contexts remain independent", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections.push(relocationSection(4, { type: 4, offset: 64n, size: 24n,
    entsize: 24n, link: 2, info: 1 }));
  fixture.elf.sections.push(relocationSection(5, { type: 4, offset: 64n, size: 24n,
    entsize: 24n, link: 2, info: 3 }));
  fixture.word(64, 0xffffn);
  const result = await parseElfRelocations(fixture.file(), fixture.elf);
  assert.equal(result?.entries.length, 2);
  assert.deepEqual(result?.entries.map(entry => entry.target), [null, null]);
  assert.deepEqual(result?.issues, []);
});
