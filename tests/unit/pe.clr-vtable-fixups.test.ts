"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseVTableFixups } from "../../analyzers/pe/clr-vtable-fixups.js";
import { MockFile } from "../helpers/mock-file.js";

const rvaToOff = (rva: number): number => rva;

void test("parseVTableFixups reports non-zero sizes when RVA is zero", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const issues: string[] = [];
  const parsed = await parseVTableFixups(new MockFile(bytes, "vt-rva0.bin"), rvaToOff, bytes.length, 0, 8, issues);
  assert.strictEqual(parsed, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("rva is 0")));
});

void test("parseVTableFixups reports RVAs when size is zero", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const issues: string[] = [];
  const parsed = await parseVTableFixups(
    new MockFile(bytes, "vt-size0.bin"),
    rvaToOff,
    bytes.length,
    0x100,
    0,
    issues
  );
  assert.strictEqual(parsed, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("size is 0")));
});

void test("parseVTableFixups parses every declared entry instead of stopping at an implementation cap", async () => {
  const base = 0x100;
  const entrySize = 8;
  const declaredEntries = 2049;
  const size = declaredEntries * entrySize;
  const bytes = new Uint8Array(base + size).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(base + 0x00, 0x1111, true);
  dv.setUint16(base + 0x04, 1, true);
  dv.setUint16(base + 0x06, 1, true);
  const lastEntryOffset = base + (declaredEntries - 1) * entrySize;
  dv.setUint32(lastEntryOffset + 0x00, 0x2222, true);
  dv.setUint16(lastEntryOffset + 0x04, 2, true);
  dv.setUint16(lastEntryOffset + 0x06, 3, true);
  const issues: string[] = [];
  const parsed = await parseVTableFixups(
    new MockFile(bytes, "vt-many.bin"),
    rvaToOff,
    bytes.length,
    base,
    size,
    issues
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.length, declaredEntries);
  assert.deepStrictEqual(parsed.at(-1), { RVA: 0x2222, Count: 2, Type: 3 });
  assert.deepStrictEqual(issues, []);
});
