import assert from "node:assert/strict";
import { test } from "node:test";
import { readSltgBlocks, sltgHeaderFields } from "../../../../../analyzers/pe/type-library/sltg-blocks.js";
import { createSltgLibrary } from "../../../../fixtures/type-library-sltg.js";

void test("SLTG follows the 1-based linked directory into physical block ranges", () => {
  const issues: string[] = [];
  assert.deepEqual(readSltgBlocks(createSltgLibrary(), issues), [
    { name: "SLTG block 1", offset: 85, length: 129 },
    { name: "SLTG block 2", offset: 214, length: 800 }
  ]);
  assert.deepEqual(issues, []);
  assert.equal(sltgHeaderFields(createSltgLibrary())[0]?.value, "3");
  assert.deepEqual(sltgHeaderFields(new Uint8Array()), []);
});

for (const count of [0, 1, 0xffff]) {
  void test(`SLTG rejects invalid or unbounded directory size ${count}`, () => {
    const data = createSltgLibrary();
    new DataView(data.buffer).setUint16(4, count, true);
    const issues: string[] = [];
    assert.deepEqual(readSltgBlocks(data, issues), []);
    assert.ok(issues.length);
  });
}

void test("SLTG rejects unexpected directory magic", () => {
  const data = createSltgLibrary();
  data[52] = 0;
  const issues: string[] = [];
  assert.deepEqual(readSltgBlocks(data, issues), []);
  assert.match(issues.join(), /magic is invalid/);
});

for (const index of [0, 3]) {
  void test(`SLTG rejects missing or invalid first block ${index}`, () => {
    const data = createSltgLibrary();
    new DataView(data.buffer).setUint16(10, index, true);
    const issues: string[] = [];
    assert.deepEqual(readSltgBlocks(data, issues), []);
    assert.ok(issues.length);
  });
}

void test("SLTG detects a cycle in the directory chain", () => {
  const data = createSltgLibrary();
  new DataView(data.buffer).setUint16(42, 1, true);
  const issues: string[] = [];
  assert.equal(readSltgBlocks(data, issues).length, 1);
  assert.match(issues.join(), /cycle/);
});
