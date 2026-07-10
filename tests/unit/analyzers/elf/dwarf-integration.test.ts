"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { createElfDwarfFile } from "../../../fixtures/elf-dwarf-file.js";

void test("parseElf connects named DWARF sections to the common analyzer", async () => {
  const elf = await parseElf(createElfDwarfFile());

  assert.equal(elf?.dwarf?.units.length, 1);
  assert.equal(elf?.dwarf?.units[0]?.root?.name, "main.c");
  assert.equal(elf?.dwarf?.units[0]?.root?.producer, "fixture compiler");
  assert.deepEqual(elf?.dwarf?.issues, []);
});
