import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfSymbolVersions } from "../../../../analyzers/elf/symbol-versions.js";
import { elfVersionFixture } from "../../../fixtures/elf-versions.js";

void test("decodes version definitions, requirements and hidden indices", async () => {
  const fixture = elfVersionFixture();
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result, {
    definitions: [{ index: 2, flags: 0, hash: 0x1234, names: ["LIB_1"] }],
    requirements: [{ file: "libsample.so", versions: [
      { index: 3, flags: 0, hash: 0, name: "LIB_2" }
    ] }], symbols: [0, 0x8002], issues: []
  });
});

void test("decodes big endian version records", async () => {
  const fixture = elfVersionFixture("big");
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.equal(result?.definitions[0]?.names[0], "LIB_1");
  assert.equal(result?.requirements[0]?.versions[0]?.index, 3);
  assert.deepEqual(result?.issues, []);
});

void test("warns on truncated version data without throwing", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[3]!.size = 19n;
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.deepEqual(result?.definitions, []);
  assert.match(result!.issues.join(" "), /truncated/);
});

void test("rejects overlapping version auxiliary records", async () => {
  const fixture = elfVersionFixture();
  fixture.view.setUint32(76, 1, true);
  const result = await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2);
  assert.match(result!.issues.join(" "), /auxiliary/);
});

void test("returns null when no version metadata exists", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections = [];
  assert.equal(await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 0), null);
});
