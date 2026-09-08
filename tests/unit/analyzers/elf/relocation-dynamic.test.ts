import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readElfRelocationTags } from "../../../../analyzers/elf/relocation-dynamic.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`reads ELF${bits} ${order} dynamic tags and stops at DT_NULL`, async () => {
      const fixture = dynamicRelocationFixture(bits, order);
      fixture.installTags();
      const issues: string[] = [];

      const tags = await readElfRelocationTags(
        createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, issues);

      assert.deepEqual(tags, fixture.tags);
      assert.deepEqual(issues, []);
    });
  }
}

void test("reads SHT_DYNAMIC without a PT_DYNAMIC and ignores repeatable tags", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(1, 1n);
  fixture.installTags();
  const segment = fixture.elf.programHeaders.pop()!;
  fixture.elf.sections.push(relocationSection(4, {
    type: 6, offset: segment.offset, size: segment.filesz
  }));
  const issues: string[] = [];

  const tags = await readElfRelocationTags(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, issues);

  assert.equal(tags.get(7), 0x1040n);
  assert.equal(tags.has(1), false);
  assert.deepEqual(issues, []);
});

void test("conflicting single-valued tags stay invalid after later repetitions", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.clear();
  fixture.tags.set(7, 0x1040n).set(8, 0n).set(9, 0n).set(10, 0n);
  fixture.installTags();
  fixture.word(784, 7n);
  fixture.word(792, 0x1040n);
  fixture.word(800, 7n);
  fixture.word(808, 0x1080n);
  fixture.word(816, 7n);
  fixture.word(824, 0x1040n);
  const issues: string[] = [];

  const tags = await readElfRelocationTags(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, issues);

  assert.equal(tags.has(7), false);
  assert.match(issues.join(" "), /Conflicting/);
});

void test("truncated ranges, partial entries and missing terminators are visible", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.installTags();
  fixture.elf.programHeaders[1]!.filesz = 257n;
  const issues: string[] = [];

  assert.equal((await readElfRelocationTags(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, issues)).size, 0);
  fixture.elf.programHeaders[1]!.filesz = 17n;
  await readElfRelocationTags(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, issues);

  assert.match(issues.join(" "), /truncated/);
  assert.match(issues.join(" "), /partial/);
  assert.match(issues.join(" "), /DT_NULL/);
});
