import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfRelocations } from "../../../../analyzers/elf/relocations.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
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
