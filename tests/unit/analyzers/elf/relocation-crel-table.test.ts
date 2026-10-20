import assert from "node:assert/strict";
import { test } from "node:test";
import { collectElfCrelDynamicTable } from "../../../../analyzers/elf/relocation-crel-table.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";

void test("DT_CREL is bounded by the containing file-backed segment", () => {
  const fixture = dynamicRelocationFixture();
  const issues: string[] = [];
  // LLVM experimental DT_CREL = 0x40000026, no size tag.
  fixture.tags.set(0x40000026, 0x1040n);
  const table = collectElfCrelDynamicTable(fixture.elf, fixture.tags, issues);
  assert.equal(table?.offset, 64);
  assert.equal(table?.size, fixture.bytes.length - 64);
  assert.equal(table?.entrySize, 1);
  assert.deepEqual(issues, []);
});
void test("absent DT_CREL and invalid memory-only or negative addresses", () => {
  const fixture = dynamicRelocationFixture();
  const issues: string[] = [];
  assert.equal(collectElfCrelDynamicTable(fixture.elf, fixture.tags, issues), null);
  fixture.tags.set(0x40000026, 0x1400n); // At file-backed end; not a valid cursor.
  assert.equal(collectElfCrelDynamicTable(fixture.elf, fixture.tags, issues), null);
  fixture.tags.set(0x40000026, -1n);
  assert.equal(collectElfCrelDynamicTable(fixture.elf, fixture.tags, issues), null);
  assert.equal(issues.length, 2);
});
void test("DT_CREL rejects segments whose physical range exceeds the file", () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(0x40000026, 0x1040n);
  fixture.elf.programHeaders[0]!.offset = BigInt(fixture.bytes.length);
  const issues: string[] = [];
  assert.equal(collectElfCrelDynamicTable(fixture.elf, fixture.tags, issues), null);
  assert.match(issues[0]!, /invalid PT_LOAD/);
});
