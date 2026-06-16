"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeLayoutWarnings } from "../../../../../analyzers/pe/layout/warnings.js";
import {
  createIndexedSection,
  createWindowsLayoutSubject,
  DEFAULT_FILE_ALIGNMENT
} from "../../../../fixtures/pe-layout-warning-subject.js";

void test("collectPeLayoutWarnings allows Linux ReadyToRun low-alignment RVA gaps", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, 0x00010200, DEFAULT_FILE_ALIGNMENT),
    createIndexedSection(1, 0x00030200, DEFAULT_FILE_ALIGNMENT * 2)
  );
  // .NET ReadyToRun: AMD64 0x8664 XOR Linux OS override 0x7B79.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/pedecoder.h
  pe.coff.Machine = 0xfd1d;
  pe.opt.SectionAlignment = DEFAULT_FILE_ALIGNMENT;
  pe.opt.FileAlignment = DEFAULT_FILE_ALIGNMENT;

  const warnings = collectPeLayoutWarnings(pe);

  assert.ok(warnings.every(warning => !/not adjacent in RVA order/i.test(warning)));
  assert.ok(warnings.every(warning => !/must match its VirtualAddress/i.test(warning)));
});
