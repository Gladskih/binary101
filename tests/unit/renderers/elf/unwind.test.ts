import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfUnwindTableModel, renderElfUnwind } from "../../../../renderers/elf/unwind.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { parseElfUnwind } from "../../../../analyzers/elf/unwind.js";
import { elfUnwindFixture } from "../../../fixtures/elf-unwind.js";

void test("renders CIE metadata and paged FDE instructions", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.unwind = await parseElfUnwind(fixture.file(), fixture.elf);
  const section = fixture.elf.unwind[0]!;
  section.cies[0]!.personality = { address: 4096n, indirect: true };
  section.issues.push("<warning>");
  const model = createElfUnwindTableModel(section);
  assert.equal(model.rowCount, 1);
  assert.equal(model.sortValueAt(0, 2), "0x2000");
  assert.match(model.rowAt(0)!.cells[5]!.html, /advance_loc/);
  assert.equal(model.rowAt(99), null);
  assert.equal(model.sortValueAt(99, 0), "");
  assert.equal(getElfPagedTableModel(fixture.elf, "elf-unwind-1")?.rowCount, 1);
  const out: string[] = [];
  renderElfUnwind(fixture.elf, out);
  assert.match(out.join(""), /Indirect at 0x1000/);
  assert.match(out.join(""), /zR/);
  assert.match(out.join(""), /&lt;warning>/);
});

void test("renders an unreadable unwind section with a warning", () => {
  const fixture = elfUnwindFixture();
  fixture.elf.unwind = [{ sectionIndex: 99, cies: [], fdes: [], issues: ["truncated"] }];
  const out: string[] = [];
  renderElfUnwind(fixture.elf, out);
  assert.match(out.join(""), /truncated/);
});

void test("omits absent unwind information", () => {
  const out: string[] = [];
  renderElfUnwind(elfUnwindFixture().elf, out);
  assert.deepEqual(out, []);
});
