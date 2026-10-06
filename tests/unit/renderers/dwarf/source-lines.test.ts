import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { renderDwarfSourceLines } from "../../../../renderers/dwarf/source-lines.js";
import { createDwarfSemanticFixture } from "../../../fixtures/dwarf-semantic-fixture.js";

void test("source lines show statement meaning, source hashes, and empty file sizes without addresses", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;
  program.files[0]!.size = 0n;
  program.files[0]!.md5 = new Uint8Array(16);
  program.rows[0] = { ...program.rows[0]!, line: 7n, column: 3n,
    basicBlock: true, prologueEnd: true, epilogueBegin: true,
    discriminator: 2n, isa: 1n, operationIndex: 1n };

  const html = renderDwarfSourceLines(dwarf);

  assert.ok(html.includes("/project/src/main.c"));
  assert.ok(html.includes("00000000000000000000000000000000"));
  assert.ok(html.includes('class="dwarfTable__numeric">0</td>'));
  assert.match(html, /statement, basic block, prologue end, epilogue begin, discriminator 2, ISA 1, operation 1/);
  assert.ok(!html.includes("0x1000"));
});

void test("source lines expose missing files and omit disclosures without mappings", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;
  program.rows = [{ ...program.rows[0]!, file: 99n, isStatement: false }];

  assert.match(renderDwarfSourceLines(dwarf), /unresolved file 99/);
  program.files[0]!.path = "";
  program.files[0]!.directoryIndex = null;
  dwarf.units = [];
  assert.match(renderDwarfSourceLines(dwarf), /\(empty path\)/);
  program.rows = [];
  assert.ok(!renderDwarfSourceLines(dwarf).includes("<details>"));
  program.files = [];
  assert.ok(!renderDwarfSourceLines(dwarf).includes("<table"));
  dwarf.linePrograms = [];
  assert.equal(renderDwarfSourceLines(dwarf), "");
});
