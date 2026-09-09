import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfSymbolVersions } from "../../../../analyzers/elf/symbol-versions.js";
import { elfVersionFixture } from "../../../fixtures/elf-versions.js";

void test("warns for unsupported definition and requirement revisions", async () => {
  const fixture = elfVersionFixture();
  fixture.view.setUint16(64, 2, true);
  fixture.view.setUint16(128, 2, true);
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result?.definitions, []);
  assert.deepEqual(result?.requirements, []);
  assert.equal(result?.issues.length, 2);
});

void test("warns when a declared chain terminates early", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[3]!.info = 2;
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.match(result!.issues.join(" "), /ends early/);
});

void test("warns when the chain continues after its declared count", async () => {
  const fixture = elfVersionFixture();
  fixture.view.setUint32(80, 28, true);
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.match(result!.issues.join(" "), /beyond its declared count/);
});

void test("warns for a missing definition auxiliary name", async () => {
  const fixture = elfVersionFixture();
  fixture.view.setUint16(70, 0, true);
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result?.definitions[0]?.names, []);
  assert.match(result!.issues.join(" "), /no auxiliary name/);
});

void test("follows definition parent names", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[3]!.size = 36n;
  fixture.view.setUint16(70, 2, true);
  fixture.view.setUint32(88, 8, true);
  fixture.view.setUint32(92, 20, true);
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result?.definitions[0]?.names, ["LIB_1", "LIB_2"]);
  assert.deepEqual(result?.issues, []);
});
