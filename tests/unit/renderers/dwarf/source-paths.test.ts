import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { dwarfSourcePath, dwarfLineFile } from "../../../../renderers/dwarf/source-paths.js";
import { createDwarfSemanticFixture } from "../../../fixtures/dwarf-semantic-fixture.js";

void test("source paths resolve legacy directory indexes against the compilation directory", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;

  assert.equal(dwarfSourcePath(program, program.files[0]!, dwarf.units[0]), "/project/src/main.c");
  assert.equal(dwarfSourcePath(program, { path: "/absolute/main.c", directoryIndex: 0n }, dwarf.units[0]),
    "/absolute/main.c");
  assert.equal(dwarfSourcePath(program, { path: "C:\\project\\main.c", directoryIndex: null }, undefined),
    "C:\\project\\main.c");
  assert.equal(dwarfSourcePath(program, { path: "main.c", directoryIndex: 0n }, dwarf.units[0]), "/project/main.c");
  assert.equal(dwarfLineFile(program, 1n), program.files[0]);
  assert.equal(dwarfLineFile(program, 0n), undefined);
  assert.equal(dwarfLineFile(program, -1n), undefined);
  assert.equal(dwarfLineFile(program, 1n << 64n), undefined);
});

void test("DWARF 5 directory and file indexes start at zero", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = { ...dwarf.linePrograms[0]!, version: 5, directories: ["/source" ] };

  assert.equal(dwarfSourcePath(program, { path: "main.c", directoryIndex: 0n }, dwarf.units[0]), "/source/main.c");
  assert.equal(dwarfSourcePath(program, { path: "main.c", directoryIndex: null }, undefined), "main.c");
  assert.equal(dwarfLineFile(program, 0n), program.files[0]);
});
