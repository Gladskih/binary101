import { dwarfUnitRoot } from "../../../../analyzers/dwarf/attribute-values.js";
"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../../../analyzers/pe/index.js";
import {
  createPeCompressedDwarfFile,
  createPeDwarfFile, createPeSemanticDwarfFile
} from "../../../fixtures/pe-dwarf-file.js";

void test("parsePe connects long COFF-named DWARF sections to the common analyzer", async () => {
  const pe = await parsePe(createPeDwarfFile());

  assert.equal(pe?.dwarf?.units.length, 1);
  assert.equal(dwarfUnitRoot(pe?.dwarf?.units[0])?.name, "main.c");
  assert.equal(dwarfUnitRoot(pe?.dwarf?.units[0])?.producer, "fixture compiler");
  assert.match(pe?.dwarf?.issues.join(" ") ?? "", /statement list.*does not identify/);
});

void test("parsePe decompresses GNU zlib DWARF sections", async () => {
  const pe = await parsePe(createPeCompressedDwarfFile());

  assert.equal(dwarfUnitRoot(pe?.dwarf?.units[0])?.name, "main.c");
  assert.equal(pe?.dwarf?.sections[0]?.compressed, true);
  assert.equal(pe?.dwarf?.sections[0]?.status, "decoded");
  assert.deepEqual(pe?.dwarf?.issues, []);
});

void test("pe preserves complete DWARF program entities and source coordinates", async () => {
  const parsed = await parsePe(createPeSemanticDwarfFile());

  assert.equal(parsed?.dwarf?.units[0]?.dies.length, 4);
  assert.equal(parsed?.dwarf?.linePrograms[0]?.files[0]?.path, "main.c");
  assert.deepEqual(parsed?.dwarf?.issues, []);
});
