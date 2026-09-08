import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readElfDynamicEntries } from "../../../../analyzers/elf/dynamic-entries.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";

void test("shared dynamic decoding preserves repeated DT_NEEDED entries", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.clear();
  fixture.tags.set(1, 1n).set(2, 2n);
  fixture.installTags();
  fixture.word(784, 1n);

  const entries = await readElfDynamicEntries(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, []);

  assert.deepEqual(entries, [{ tag: 1, value: 1n }, { tag: 1, value: 2n }]);
});

void test("short reads and tags outside safe numeric range cannot trigger DataView exceptions", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.clear();
  fixture.tags.set(7, 0n);
  fixture.installTags();
  fixture.word(768, 1n << 63n);
  const issues: string[] = [];
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);

  assert.deepEqual(await readElfDynamicEntries(reader, fixture.elf, []), []);
  assert.deepEqual(await readElfDynamicEntries({ ...reader,
    read: async () => new DataView(new ArrayBuffer(0)) }, fixture.elf, issues), []);
  assert.match(issues.join(" "), /DT_NULL/);
});
