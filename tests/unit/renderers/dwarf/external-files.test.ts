import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDwarfExternalFiles, renderDwarfPackages } from "../../../../renderers/dwarf/external-files.js";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import { createDwarfPackageFixture, createDwarfSplitContents,
  splitSkeleton, splitSkeletonAbbreviations } from "../../../fixtures/dwarf-split-fixture.js";

void test("related file tables name missing split files and escape filenames", async () => {
  const fixture = createDwarfSectionFile([{ name: ".debug_info", bytes: splitSkeleton("<source>.dwo") },
    { name: ".debug_abbrev", bytes: splitSkeletonAbbreviations() }]);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  const html = renderDwarfExternalFiles(parsed);
  assert.match(html, /&lt;source>.dwo/);
  assert.match(html, /External file required/);
  assert.match(html, /Full debug information for this compilation unit/);
});

void test("related files show a decoded matching split unit and supplementary roles", async () => {
  const fixture = createDwarfSectionFile([{ name: ".debug_info", bytes: splitSkeleton() },
    { name: ".debug_abbrev", bytes: splitSkeletonAbbreviations() }, ...createDwarfSplitContents()]);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  assert.match(renderDwarfExternalFiles(parsed), /Matching split unit decoded/);
  parsed.supplementaryFile = { version: 5, isSupplementary: true, filename: "", checksum: new Uint8Array() };
  assert.match(renderDwarfExternalFiles(parsed), /This file.*Shared debug information/);
  assert.match(renderDwarfExternalFiles(parsed), /Supplementary object decoded locally/);
  parsed.supplementaryFile = { ...parsed.supplementaryFile, isSupplementary: false, filename: "shared.debug" };
  parsed.alternateFile = { filename: "shared.gnu", buildId: Uint8Array.of(7) };
  assert.match(renderDwarfExternalFiles(parsed), /shared.debug/);
  assert.match(renderDwarfExternalFiles(parsed), /shared.gnu.*Shared GNU debug information/);
});

void test("package tables describe their contents and encoding instead of address matrices", async () => {
  const fixture = createDwarfPackageFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  assert.match(renderDwarfPackages(parsed), /Compilation units/);
  assert.match(renderDwarfPackages(parsed), /DWARF package version 5/);
  assert.doesNotMatch(renderDwarfPackages(parsed), /0x/);
  parsed.packageIndexes![0]!.sectionName = ".debug_tu_index";
  assert.match(renderDwarfPackages(parsed), /Shared types/);
  assert.equal(renderDwarfPackages({ sections: [], units: [], linePrograms: [], issues: [] }), "");
  assert.equal(renderDwarfExternalFiles({ sections: [], units: [], linePrograms: [], issues: [] }), "");
});
