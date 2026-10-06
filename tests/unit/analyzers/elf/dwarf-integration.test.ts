import { dwarfUnitRoot } from "../../../../analyzers/dwarf/attribute-values.js";
"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import {
  createElfCompressedDwarfFile,
  createElfDwarfFile, createElfSemanticDwarfFile
} from "../../../fixtures/elf-dwarf-file.js";

void test("parseElf connects named DWARF sections to the common analyzer", async () => {
  const elf = await parseElf(createElfDwarfFile());

  assert.equal(elf?.dwarf?.units.length, 1);
  assert.equal(dwarfUnitRoot(elf?.dwarf?.units[0])?.name, "main.c");
  assert.equal(dwarfUnitRoot(elf?.dwarf?.units[0])?.producer, "fixture compiler");
  assert.match(elf?.dwarf?.issues.join(" ") ?? "", /statement list.*does not identify/);
});

void test("parseElf decompresses ELF64 SHF_COMPRESSED zlib DWARF sections", async () => {
  const elf = await parseElf(createElfCompressedDwarfFile());

  assert.equal(dwarfUnitRoot(elf?.dwarf?.units[0])?.name, "main.c");
  assert.equal(elf?.dwarf?.sections[0]?.compressed, true);
  assert.equal(elf?.dwarf?.sections[0]?.status, "decoded");
  assert.deepEqual(elf?.dwarf?.issues, []);
});

void test("elf preserves complete DWARF program entities and source coordinates", async () => {
  const parsed = await parseElf(createElfSemanticDwarfFile());

  assert.equal(parsed?.dwarf?.units[0]?.dies.length, 4);
  assert.equal(parsed?.dwarf?.linePrograms[0]?.files[0]?.path, "main.c");
  assert.deepEqual(parsed?.dwarf?.issues, []);
});
