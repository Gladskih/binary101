import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfSplitFilename, dwarfSplitIdentity, readDwarfExternalFiles,
  validateDwarfSplitFiles } from "../../../../analyzers/dwarf/external-files.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";

void test("split identities and filenames use standard or GNU fields without fabricating missing metadata", () => {
  const standard = createListUnit(5, [{ name: 0x76, form: 8, value: { kind: "string", value: "unit.dwo" } }]);
  const gnu = createListUnit(4, [listAttribute(0x2131, 7, 7n),
    { name: 0x2130, form: 8, value: { kind: "string", value: "gnu.dwo" } }]);
  assert.equal(dwarfSplitIdentity({ ...standard, dwoId: 2n }), 2n);
  assert.equal(dwarfSplitFilename(standard), "unit.dwo");
  assert.equal(dwarfSplitIdentity(gnu), 7n);
  assert.equal(dwarfSplitFilename(gnu), "gnu.dwo");
  assert.equal(dwarfSplitFilename(createListUnit(5)), null);
  assert.equal(dwarfSplitIdentity(createListUnit(5)), null);
});

void test("split references require a matching non-null signature and skip split-only owners", () => {
  const standard = createListUnit(5, [{ name: 0x76, form: 8, value: { kind: "string", value: "unit.dwo" } }]);
  const issues: string[] = [];
  const available: string[] = [];
  validateDwarfSplitFiles([standard, { ...standard, sectionName: ".debug_info.dwo" }], issues);
  validateDwarfSplitFiles([{ ...standard, dwoId: 2n }, { ...standard, sectionName: ".debug_info.dwo", dwoId: 2n }], available);
  assert.match(issues.join(" "), /unit.dwo.*not present/);
  assert.deepEqual(available, []);
  const standalone: string[] = [];
  validateDwarfSplitFiles([{ ...standard, sectionName: ".debug_info.dwo", dwoId: 2n }], standalone);
  assert.deepEqual(standalone, []);
});

void test("external section decoding retains supplementary and GNU alternate metadata", async () => {
  const issues: string[] = [];
  const parsed = await readDwarfExternalFiles(dwarfMacroSources([
    { name: ".debug_sup", bytes: [5, 0, 0, 65, 0, 1, 7] },
    { name: ".gnu_debugaltlink", bytes: [66, 0, 8] }
  ]), "little", issues);
  assert.equal(parsed.supplementaryFile?.filename, "A");
  assert.equal(parsed.alternateFile?.filename, "B");
  assert.deepEqual(issues, []);
  assert.deepEqual(await readDwarfExternalFiles(new Map(), "big", issues), {});
});

void test("malformed external sections remain absent from results with visible diagnostics", async () => {
  const issues: string[] = [];
  assert.deepEqual(await readDwarfExternalFiles(dwarfMacroSources([
    { name: ".debug_sup", bytes: [] }, { name: ".gnu_debugaltlink", bytes: [] }
  ]), "little", issues), {});
  assert.equal(issues.length, 2);
});
