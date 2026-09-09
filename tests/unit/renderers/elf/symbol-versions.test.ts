import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfVersionedSymbolName, renderElfSymbolVersions } from
  "../../../../renderers/elf/symbol-versions.js";
import { elfVersionFixture } from "../../../fixtures/elf-versions.js";
import { parseElfSymbolVersions } from "../../../../analyzers/elf/symbol-versions.js";

const symbol = { index: 1, name: "example", value: 0n, size: 0n, bind: 1,
  bindName: "GLOBAL", type: 2, typeName: "FUNC", visibility: 0,
  visibilityName: "DEFAULT", shndx: 1 };

void test("formats default, hidden, required and unresolved versions", async () => {
  const fixture = elfVersionFixture();
  const versions = (await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2))!;
  fixture.elf.symbolVersions = versions;
  assert.equal(createElfVersionedSymbolName(fixture.elf)(symbol), "example@LIB_1");
  versions.symbols[1] = 2;
  assert.equal(createElfVersionedSymbolName(fixture.elf)(symbol), "example@@LIB_1");
  versions.symbols[1] = 3;
  assert.equal(createElfVersionedSymbolName(fixture.elf)({ ...symbol, shndx: 0 }), "example@LIB_2");
  versions.symbols[1] = 99;
  assert.equal(createElfVersionedSymbolName(fixture.elf)(symbol), "example@#99");
  versions.symbols[1] = 1;
  assert.equal(createElfVersionedSymbolName(fixture.elf)(symbol), "example");
});

void test("renders escaped version metadata and warnings", async () => {
  const fixture = elfVersionFixture();
  fixture.elf.symbolVersions = (await parseElfSymbolVersions(fixture.file(), fixture.elf, [], 2))!;
  fixture.elf.symbolVersions.issues.push("<invalid>");
  const out: string[] = [];
  renderElfSymbolVersions(fixture.elf, out);
  assert.match(out.join(""), /libsample.so/);
  assert.match(out.join(""), /LIB_1/);
  assert.match(out.join(""), /&lt;invalid>/);
});

void test("omits absent version metadata", () => {
  const fixture = elfVersionFixture();
  const out: string[] = [];
  renderElfSymbolVersions(fixture.elf, out);
  assert.deepEqual(out, []);
  assert.equal(createElfVersionedSymbolName(fixture.elf)(symbol), "example");
});

