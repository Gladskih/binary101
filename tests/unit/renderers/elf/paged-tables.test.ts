"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfParseResult } from "../../../../analyzers/elf/types.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";

void test("getElfPagedTableModel exposes NativeAOT reflection rows", () => {
  const elf = {
    nativeAot: {
      reflection: {
        scopes: [{
          name: "App",
          moduleName: "App.dll",
          version: { major: 1, minor: 0, build: 0, revision: 0 },
          types: [{ namespace: "", name: "Program", methods: ["Main"] }]
        }]
      }
    }
  } as ElfParseResult;

  const model = getElfPagedTableModel(elf, "native-aot-reflection-types");

  assert.equal(model?.rowCount, 1);
  assert.equal(model?.rowAt(0)?.cells[1]?.sortValue, "Program");
  assert.equal(getElfPagedTableModel(elf, "unknown"), null);
});
