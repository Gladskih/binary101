"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfParseResult } from "../../../../analyzers/elf/types.js";
import { renderElfNativeAot } from "../../../../renderers/elf/native-aot.js";

const subject = (): ElfParseResult => ({
  nativeAot: {
    status: "confirmed",
    layout: "nativeaot-readytorun-pointer-range-v1",
    modulePointerRva: 0x2100,
    headerRva: 0x2000,
    majorVersion: 16,
    minorVersion: 0,
    sections: [{ type: 313, rva: 0x3000, size: 32 }],
    reflection: {
      scopes: [{
        name: "Sample",
        moduleName: "Sample.dll",
        version: { major: 1, minor: 0, build: 0, revision: 0 },
        types: [{ namespace: "Demo", name: "Program", methods: ["Main"], fields: ["Count"] }]
      }]
    }
  },
  ident: {} as ElfParseResult["ident"],
  header: {} as ElfParseResult["header"],
  programHeaders: [],
  sections: [],
  issues: [],
  is64: true,
  littleEndian: true,
  fileSize: 0
});

void test("renderElfNativeAot explains evidence and renders structured metadata", () => {
  const output: string[] = [];

  renderElfNativeAot(subject(), output);

  const html = output.join("");
  assert.ok(html.includes("NativeAOT metadata"));
  assert.ok(html.includes("relative REL/RELA relocations"));
  assert.ok(html.includes("Embedded reflection metadata"));
  assert.ok(html.includes("Sample.dll"));
  assert.ok(html.includes("Demo.Program"));
  assert.ok(html.includes('class="table nativeAotSectionsTable"'));
});

void test("renderElfNativeAot omits absent metadata", () => {
  const elf = subject();
  delete elf.nativeAot;
  const output: string[] = [];

  renderElfNativeAot(elf, output);

  assert.deepEqual(output, []);
});
