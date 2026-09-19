"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { renderElfDebug } from "../../../../renderers/elf/debug.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarf4SectionsFixture } from "../../../fixtures/dwarf-sections-fixture.js";

void test("renderElfDebug renders .comment and .gnu_debuglink", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfDebug(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Build / debug"));
  assert.ok(html.includes(".comment"));
  assert.ok(html.includes(expectDefined(expected.commentStrings[0])));
  assert.ok(html.includes(expected.debugLinkFileName));
});

void test("renders escaped Go version and module records", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  elf.goBuildInfo = { version: "go<version>", moduleInfo: "path\t<module>\nmod\tmain\tv1\thash\n" };
  const out: string[] = [];
  renderElfDebug(elf, out);
  assert.match(out.join(""), /Go toolchain: go&lt;version>/);
  assert.match(out.join(""), /<td>path<\/td><td>&lt;module><\/td>/);
  assert.match(out.join(""), /<td>v1 hash<\/td>/);
  assert.doesNotMatch(out.join(""), /<module>|<version>/);
});

void test("renderElfDebug renders common DWARF analysis", async () => {
  const { file } = createElfMetadataFile();
  const elf = expectDefined(await parseElf(file));
  const dwarfFixture = createDwarf4SectionsFixture();
  elf.dwarf = await analyzeDwarf(dwarfFixture.file, dwarfFixture.sections, true);
  const out: string[] = [];

  renderElfDebug(elf, out);

  const html = out.join("");
  assert.ok(html.includes("DWARF debug information (1 unit)"));
  assert.ok(html.includes("main.c"));
});
