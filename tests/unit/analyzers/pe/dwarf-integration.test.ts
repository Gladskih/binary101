"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../../../analyzers/pe/index.js";
import {
  createPeCompressedDwarfFile,
  createPeDwarfFile
} from "../../../fixtures/pe-dwarf-file.js";

void test("parsePe connects long COFF-named DWARF sections to the common analyzer", async () => {
  const pe = await parsePe(createPeDwarfFile());

  assert.equal(pe?.dwarf?.units.length, 1);
  assert.equal(pe?.dwarf?.units[0]?.root?.name, "main.c");
  assert.equal(pe?.dwarf?.units[0]?.root?.producer, "fixture compiler");
  assert.deepEqual(pe?.dwarf?.issues, []);
});

void test("parsePe decompresses GNU zlib DWARF sections", async () => {
  const pe = await parsePe(createPeCompressedDwarfFile());

  assert.equal(pe?.dwarf?.units[0]?.root?.name, "main.c");
  assert.equal(pe?.dwarf?.sections[0]?.compressed, true);
  assert.equal(pe?.dwarf?.sections[0]?.status, "decoded");
  assert.deepEqual(pe?.dwarf?.issues, []);
});
