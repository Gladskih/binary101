import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfUnwindTableModel, renderElfUnwind } from "../../../../renderers/elf/unwind.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { parseElfUnwind } from "../../../../analyzers/elf/unwind.js";
import { elfSegmentUnwindFixture, elfUnwindFixture } from "../../../fixtures/elf-unwind.js";
import { getElfLazySections } from "../../../../renderers/elf/lazy-sections.js";

void test("sectionless AArch64 unwind links to its FDEs and shows the recorded signing PC", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.header.machine = 183;
  fixture.bytes.set([0x2b, 2, 1], 102); // SP+PC, one code alignment unit ahead.
  fixture.elf.unwind = await parseElfUnwind(fixture.file(), fixture.elf);

  const panel = getElfLazySections(fixture.elf).find(section => section.key === "unwind-0");
  const model = getElfPagedTableModel(fixture.elf, "elf-unwind-segment-1");
  assert.match(panel?.title ?? "", /PT_GNU_EH_FRAME #1/);
  assert.equal(model?.rowCount, 1);
  assert.match(model.rowAt(0)?.cells[5]?.html ?? "", /Signed with SP \+ PC \(0x2002\)/);
});

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
  assert.equal(model.columns[5]!.className, "");
  assert.equal(model.rowAt(0)!.cells[5]!.className, "");
  assert.equal(model.columns[0]!.className, "peNumeric");
  assert.equal(model.rowAt(0)!.cells[0]!.className, "peNumeric");
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

void test("renders the decoded set_loc operand as an address", async () => {
  const fixture = elfUnwindFixture();
  const [section] = await parseElfUnwind(fixture.file(), fixture.elf);
  Object.assign(section!.fdes[0]!.instructions[0]!, { operation: "set_loc", operands: [8200n] });

  const model = createElfUnwindTableModel(section!);

  assert.match(model.rowAt(0)!.cells[5]!.html, /set_loc<\/td><td>0x2008<\/td>/);
});

void test("omits absent unwind information", () => {
  const out: string[] = [];
  renderElfUnwind(elfUnwindFixture().elf, out);
  assert.deepEqual(out, []);
});
