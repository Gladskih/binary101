"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeHeaderFieldWarnings } from "../../analyzers/pe/layout/header-field-warnings.js";
import { createWindowsLayoutSubject } from "../fixtures/pe-layout-warning-subject.js";

void test("collectPeHeaderFieldWarnings reports section counts above the loader limit", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.NumberOfSections = 97;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), [
    "NumberOfSections is greater than 96; the Windows loader limits image section count to 96."
  ]);
});

void test("collectPeHeaderFieldWarnings accepts the Windows loader section count limit", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.NumberOfSections = 96;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});
