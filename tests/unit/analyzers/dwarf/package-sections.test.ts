import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfPackageSectionName, dwarfSplitBaseName, isDwarfSplitSection } from "../../../../analyzers/dwarf/package-sections.js";

void test("package section identifiers retain the different GNU2 and standard5 encodings", () => {
  // DWARF5 Table7.1 versus LLVM DWARFUnitIndex.cpp v2 mappings.
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8].map(id => dwarfPackageSectionName(5, id)),
    [".debug_info.dwo", null, ".debug_abbrev.dwo", ".debug_line.dwo", ".debug_loclists.dwo",
      ".debug_str_offsets.dwo", ".debug_macro.dwo", ".debug_rnglists.dwo"]);
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8].map(id => dwarfPackageSectionName(2, id)),
    [".debug_info.dwo", ".debug_types.dwo", ".debug_abbrev.dwo", ".debug_line.dwo", ".debug_loc.dwo",
      ".debug_str_offsets.dwo", ".debug_macinfo.dwo", ".debug_macro.dwo"]);
  assert.equal(dwarfPackageSectionName(5, 0), null);
  assert.equal(dwarfPackageSectionName(2, 99), null);
});

void test("split section normalization applies only to known DWO sections", () => {
  assert.equal(dwarfSplitBaseName(".debug_info.dwo"), ".debug_info");
  assert.equal(dwarfSplitBaseName(".debug_str.dwo"), ".debug_str");
  assert.equal(isDwarfSplitSection(".debug_ranges.dwo"), true);
  assert.equal(dwarfSplitBaseName(".debug_future.dwo"), ".debug_future.dwo");
  assert.equal(dwarfSplitBaseName(".debug_info"), ".debug_info");
  assert.equal(isDwarfSplitSection(".debug_addr"), false);
});
