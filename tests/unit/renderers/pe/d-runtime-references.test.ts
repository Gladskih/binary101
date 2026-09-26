import assert from "node:assert/strict";
import { test } from "node:test";
import { createDRuntimeReferenceTableModel } from "../../../../renderers/pe/d-runtime-references.js";
import { createDTestModule, D_TEST_MEMORY } from "../../../fixtures/d-runtime.js";

void test("resolves imported names and keeps local classes explicitly as references", () => {
  const module = createDTestModule();
  const model = createDRuntimeReferenceTableModel([module]);

  assert.equal(model.rowCount, module.importedModules.length + module.localClasses.length);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html),
    [module.name, "Imported ModuleInfo", module.name, `0x${module.address.toString(16)}`]);
  assert.deepEqual(model.rowAt(module.importedModules.length)?.cells.map(cell => cell.html),
    [module.name, "Local ClassInfo reference", "", `0x${module.localClasses[0]!.toString(16)}`]);
  assert.equal(model.sortValueAt(0, model.columns.length - 1), module.address.toString());
  assert.deepEqual(model.columns.map(column => column.label),
    ["Source module", "Reference", "Target module", "Target VA"]);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.className),
    [undefined, undefined, undefined, "peNumeric"]);
  assert.equal(model.sortValueAt(0, model.columns.length), "");
  assert.equal(model.sortValueAt(model.rowCount, 0), "");
  assert.equal(model.rowAt(model.rowCount), null);
});

void test("escapes names and preserves unresolved imports", () => {
  const module = createDTestModule();
  module.name = "<name>";
  module.importedModules = [D_TEST_MEMORY.unmappedAddress];
  const model = createDRuntimeReferenceTableModel([module]);

  assert.equal(model.rowAt(0)?.cells[0]?.html, "&lt;name>");
  assert.equal(model.rowAt(0)?.cells[model.columns.length - 2]?.html, "");
});
