"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { loadClrDependency } from "../../../../../../analyzers/pe/clr/metadata-dependency-loader.js";
import { clrDependencyFile, changeDependencyU32 } from "../../../../../helpers/clr-dependency-file.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

void test("loads metadata through bounded PE/RVA readers", async () => {
  const issues: string[] = [];
  const tables = await loadClrDependency(clrDependencyFile(), issues);
  assert.ok(tables);
  assert.deepEqual(tables.customAttributes, []);
  assert.deepEqual(issues, []);
});

void test("reports missing PE and CLR directories", async () => {
  const issues: string[] = [];
  assert.equal(await loadClrDependency(new MockFile(new Uint8Array()), issues), null);
  assert.equal(await loadClrDependency(changeDependencyU32(64 + 4 + 20 + 92, 0), issues), null);
  assert.match(issues.join(";"), /no Windows PE headers/);
  assert.match(issues.join(";"), /no CLR metadata directory/);
});

for (const [offset, value] of [[0x188, 0], [0x18c, 0], [0x200, 0], [0x218, 0xffff],
  [64 + 4 + 20 + 96 + 14 * 8, 0xffff], [64 + 4 + 20 + 96 + 14 * 8 + 4, 10]]) {
  void test(`warns on absent, invalid or truncated dependency metadata at ${offset}`, async () => {
    const issues: string[] = [];
    assert.equal(await loadClrDependency(changeDependencyU32(offset!, value!), issues), null);
    assert.ok(issues.length);
  });
}

void test("reports metadata without a table stream and file read failures", async () => {
  const issues: string[] = [];
  assert.equal(await loadClrDependency(changeDependencyU32(0x216, 0), issues), null);
  assert.match(issues.join(";"), /tables are unavailable/);
  const broken = clrDependencyFile();
  broken.slice = () => { throw new Error("unreadable"); };
  assert.equal(await loadClrDependency(broken, issues), null);
  assert.match(issues.join(";"), /could not be read/);
});

void test("retains metadata and reports a truncated COR20 header", async () => {
  const issues: string[] = [];
  // ECMA-335 II.25.3.3: metadata RVA/size precede the other COR20 directories.
  const tables = await loadClrDependency(changeDependencyU32(64 + 4 + 20 + 96 + 14 * 8 + 4, 16), issues);
  assert.ok(tables);
  assert.match(issues.join(";"), /minimum COR20 header/);
  assert.match(issues.join(";"), /IMAGE_COR20_HEADER/);
});

for (const offset of [0x188, 0x18c]) {
  void test(`reports the absent metadata location field at ${offset}`, async () => {
    const issues: string[] = [];
    assert.equal(await loadClrDependency(changeDependencyU32(offset, 0), issues), null);
    assert.deepEqual(issues, ["modified.dll: CLR metadata location is absent or truncated."]);
  });
}
