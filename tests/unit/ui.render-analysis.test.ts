"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderAnalysisIntoUi } from "../../ui/render-analysis.js";

void test("renderAnalysisIntoUi renders ELF output and updates visibility flags", () => {
  const elf = {
    ident: {
      classByte: 2,
      className: "ELF64",
      dataByte: 1,
      dataName: "Little endian",
      osabi: 0,
      abiVersion: 0
    },
    header: {
      type: 2,
      typeName: "Executable",
      machine: 62,
      machineName: "x86-64",
      entry: 0x400000n,
      phoff: 0n,
      shoff: 0n,
      flags: 0,
      ehsize: 64,
      phentsize: 56,
      phnum: 0,
      shentsize: 64,
      shnum: 0,
      shstrndx: 0
    },
    programHeaders: [],
    sections: [],
    issues: [],
    is64: true,
    littleEndian: true,
    fileSize: 0
  } as unknown as ElfParseResult;
  const result: ParseForUiResult = { analyzer: "elf", parsed: elf };

  const termElement = { textContent: "", hidden: true } as unknown as HTMLElement;
  const valueElement = { innerHTML: "", hidden: true } as unknown as HTMLElement;

  renderAnalysisIntoUi(result, {
    buildPreview: () => null,
    attachGuards: () => {},
    termElement,
    valueElement
  });

  assert.equal(termElement.hidden, false);
  assert.equal(termElement.textContent, "ELF details");
  assert.equal(valueElement.hidden, false);
  assert.ok(valueElement.innerHTML.includes("Instruction sets"));
});

