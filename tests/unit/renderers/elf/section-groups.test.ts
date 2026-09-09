import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfSectionGroups } from "../../../../renderers/elf/section-groups.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import { parseElfSymbolTables } from "../../../../analyzers/elf/symbol-tables.js";

void test("renders COMDAT signatures from the shared symbol table", async () => {
  const fixture = relocationFixture();
  fixture.elf.symbolTables = await parseElfSymbolTables(fixture.file(), fixture.elf);
  fixture.elf.sections.push(relocationSection(4, { type: 17, link: 2, info: 1 }));
  fixture.elf.sectionGroups = [{ sectionIndex: 4, flags: 1, members: [1], issues: ["<invalid>"] }];
  const out: string[] = [];
  renderElfSectionGroups(fixture.elf, out);
  assert.match(out.join(""), /COMDAT/);
  assert.match(out.join(""), /target/);
  assert.match(out.join(""), /&lt;invalid>/);
});

void test("renders unresolved signatures and unreadable group flags", () => {
  const fixture = relocationFixture();
  fixture.elf.sectionGroups = [{ sectionIndex: 99, flags: null, members: [100], issues: [] }];
  const out: string[] = [];
  renderElfSectionGroups(fixture.elf, out);
  assert.match(out.join(""), /Unresolved/);
  assert.match(out.join(""), /Unknown/);
  assert.match(out.join(""), /#100/);
});

void test("omits absent groups", () => {
  const out: string[] = [];
  renderElfSectionGroups(relocationFixture().elf, out);
  assert.deepEqual(out, []);
});
