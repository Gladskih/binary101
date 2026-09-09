import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfUnwind } from "../../../../analyzers/elf/unwind.js";
import { elfUnwindFixture } from "../../../fixtures/elf-unwind.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

void test("decodes CIE and FDE structures and CFI instructions", async () => {
  const fixture = elfUnwindFixture();
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies[0]?.augmentation, "zR");
  assert.equal(result[0]?.cies[0]?.dataAlignment, -8n);
  assert.equal(result[0]?.cies[0]?.returnRegister, 16n);
  assert.equal(result[0]?.fdes[0]?.start?.address, 8192n);
  assert.equal(result[0]?.fdes[0]?.range, 32n);
  assert.equal(result[0]?.fdes[0]?.cieOffset, 0);
  assert.deepEqual(result[0]?.cies[0]?.instructions[0]?.operands, [7n, 8n]);
  assert.deepEqual(result[0]?.fdes[0]?.instructions[1]?.operands, [6n, 2n]);
  assert.deepEqual(result[0]?.issues, []);
});

void test("decodes big endian unwind records", async () => {
  const fixture = elfUnwindFixture("big");
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.fdes[0]?.start?.address, 8192n);
  assert.deepEqual(result[0]?.issues, []);
});

void test("warns for truncated records", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.sections[1]!.size = 30n;
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies.length, 1);
  assert.equal(result[0]?.fdes.length, 0);
  assert.match(result[0]!.issues.join(" "), /truncated/);
});

void test("warns for invalid CIE references", async () => {
  const fixture = elfUnwindFixture();
  fixture.view.setUint32(88, 100, true);
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.fdes.length, 0);
  assert.match(result[0]!.issues.join(" "), /CIE/);
});

void test("warns for unsupported CIE revisions and augmentation", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes[72] = 9;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /version/);
  fixture.bytes[72] = 1;
  fixture.bytes[74] = 88;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /augmentation/);
});

void test("warns on unknown CFI instructions", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes[101] = 0x3f;
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.match(result[0]!.issues.join(" "), /CFI/);
});

void test("reads debug_frame CIE identifiers and absolute CIE offsets", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.sections[1]!.name = ".debug_frame";
  fixture.view.setUint32(68, 0xffffffff, true);
  fixture.view.setUint32(88, 0, true);
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies.length, 1);
  assert.equal(result[0]?.fdes[0]?.cieOffset, 0);
  assert.deepEqual(result[0]?.issues, []);
});

void test("reports unavailable compressed and relocated unwind data", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.sections[1]!.flags = 0x800n;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /Compressed/);
  fixture.elf.sections[1]!.flags = 0n;
  fixture.elf.sections.push(relocationSection(2, { type: 4, info: 1 }));
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /relocations/);
});

void test("rejects reserved record lengths and section ranges outside the file", async () => {
  const fixture = elfUnwindFixture();
  fixture.view.setUint32(64, 0xfffffff0, true);
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /Reserved/);
  fixture.elf.sections[1]!.offset = 1n << 60n;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /outside/);
});

void test("reads an extended-length eh_frame CIE", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes.copyWithin(80, 72, 84);
  fixture.view.setUint32(64, 0xffffffff, true);
  fixture.view.setBigUint64(68, 16n, true);
  fixture.view.setUint32(76, 0, true);
  fixture.elf.sections[1]!.size = 28n;
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies[0]?.augmentation, "zR");
  assert.deepEqual(result[0]?.issues, []);
});
