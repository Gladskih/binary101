"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfParseResult } from "../../../../analyzers/elf/types.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { createNativeAotInitializerFixture } from "../../../helpers/native-aot-initializer-fixture.js";

void test("getElfPagedTableModel exposes NativeAOT reflection rows", () => {
  const elf = {
    nativeAot: {
      reflection: {
        scopes: [{
          name: "App",
          moduleName: "App.dll",
          version: { major: 1, minor: 0, build: 0, revision: 0 },
          types: [{ namespace: "", name: "Program", methods: ["Main"].map(name => ({ name })), fields: ["Count"].map(name => ({ name })) }]
        }]
      }
    }
  } as ElfParseResult;

  const model = getElfPagedTableModel(elf, "native-aot-reflection-types");

  assert.equal(model?.rowCount, 1);
  assert.equal(model?.rowAt(0)?.cells[1]?.sortValue, "Program");
  assert.equal(model?.rowAt(0)?.cells[3]?.html, "Count");
  assert.equal(model?.sortValueAt(0, 3), "Count");
  assert.equal(getElfPagedTableModel(elf, "unknown"), null);
});

void test("ELF paging resolves NativeAOT invoke and stack-trace map tables", () => {
  const elf = { nativeAot: { ...createNativeAotInitializerFixture().header,
    invokeMap: { entries: [{ flags: 0, metadataOffset: 1, declaringTypeIndex: 2,
      entrypointRva: 16, invokeStubRva: null, genericArgumentIndices: [] }], warnings: [] },
    stackTraceMap: { entries: [{ command: 0, methodRva: 32 }], warnings: [] }
  } } as unknown as ElfParseResult;

  assert.equal(getElfPagedTableModel(elf, "native-aot-invoke-map")?.rowCount, 4);
  assert.equal(getElfPagedTableModel(elf, "native-aot-stack-trace-map")?.rowCount, 5);
});
