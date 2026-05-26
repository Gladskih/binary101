"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeLayoutWarnings } from "../../analyzers/pe/layout/warnings.js";
import {
  createIndexedSection,
  createWindowsLayoutSubject,
  DEFAULT_FILE_ALIGNMENT,
  DEFAULT_SECTION_ALIGNMENT
} from "../fixtures/pe-layout-warning-subject.js";

void test("collectPeLayoutWarnings skips DOS-stub warnings for CLR native images", () => {
  const pe = createWindowsLayoutSubject(
    createIndexedSection(0, DEFAULT_SECTION_ALIGNMENT, DEFAULT_FILE_ALIGNMENT)
  );
  pe.subtype = "clr-native-image";
  // Microsoft documents NGen outputs as PE native images in the native image cache;
  // PE/COFF locates the PE header via e_lfanew, so zeroed DOS stub fields are not
  // useful layout warnings after the CLR native-image subtype is confirmed.
  // https://learn.microsoft.com/en-us/dotnet/framework/tools/ngen-exe-native-image-generator
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#overview
  pe.dos.e_cparhdr = 0;
  pe.dos.e_cp = 0;
  const warnings = collectPeLayoutWarnings(pe);
  assert.ok(!warnings.some(warning => /e_cparhdr|e_cp/i.test(warning)));
});
