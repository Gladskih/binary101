import assert from "node:assert/strict";
import { test } from "node:test";
import { createDRuntimeModuleTableModel, renderDRuntime } from "../../../../renderers/pe/d-runtime.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDDisplayModule, createDTestModule } from "../../../fixtures/d-runtime.js";

void test("renders D metadata, references, callbacks and escaped warnings", () => {
  const module = createDTestModule();
  const pe = createBasePe();
  pe.dRuntime = { modules: [module], warnings: ["<truncated>"] };
  const out: string[] = [];

  renderDRuntime(pe, out);

  assert.match(out.join(""), /1 validated modules/);
  assert.ok(out.join("").includes(module.name));
  assert.ok(out.join("").includes(`TLS constructor 0x${module.callbacks[0]!.address.toString(16)}`));
  assert.match(out.join(""), /&lt;truncated>/);
  assert.doesNotMatch(out.join(""), /<truncated>/);
  assert.match(out.join(""), /<table[^>]*data-sort-state-key="pe-d-runtime-references"/);
  assert.ok(out.join("").endsWith("</div></details></section>"));
  assert.equal(getPePagedTableModel(pe, "pe-d-runtime-modules")?.rowCount, pe.dRuntime.modules.length);
  assert.equal(getPePagedTableModel(pe, "pe-d-runtime-references")?.rowCount,
    module.importedModules.length + module.localClasses.length);
});

void test("renders diagnostic-only candidates without calling them confirmed D", () => {
  const pe = createBasePe();
  pe.dRuntime = { modules: [], warnings: ["No validated ModuleInfo"] };
  const out: string[] = [];

  renderDRuntime(pe, out);

  assert.match(out.join(""), /No validated ModuleInfo/);
  assert.doesNotMatch(out.join(""), /<table/);
});

void test("emits no section for ordinary PE images", () => {
  const out: string[] = [];

  renderDRuntime(createBasePe(), out);

  assert.deepEqual(out, []);
});

void test("provides sortable numeric fields and handles missing rows and columns", () => {
  const module = createDDisplayModule();
  module.name = "<module>";
  const model = createDRuntimeModuleTableModel([module]);

  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.sortValue), ["<module>",
    module.address.toString(), String(module.flags), String(module.index),
    String(module.importedModules.length), String(module.localClasses.length),
    `TLS constructor 0x${module.callbacks[0]!.address.toString(16)}; ` +
      `Unit test 0x${module.callbacks[1]!.address.toString(16)}`]);
  assert.equal(model.rowAt(0)?.cells[0]?.html, "&lt;module>");
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html), ["&lt;module>",
    `0x${module.address.toString(16)}`, `0x${module.flags.toString(16)}`, String(module.index),
    String(module.importedModules.length), String(module.localClasses.length),
    `TLS constructor 0x${module.callbacks[0]!.address.toString(16)}<br>` +
      `Unit test 0x${module.callbacks[1]!.address.toString(16)}`]);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.className),
    [undefined, "peNumeric", "peNumeric", "peNumeric", "peNumeric", "peNumeric", undefined]);
  assert.deepEqual(model.columns.map(column => column.label),
    ["Module", "ModuleInfo VA", "Flags", "Index", "Imports", "Local classes", "Callbacks (VA)"]);
  assert.equal(model.sortValueAt(0, 0), "<module>");
  assert.equal(model.sortValueAt(0, model.columns.length), "");
  assert.equal(model.sortValueAt(model.rowCount, 0), "");
  assert.equal(model.rowAt(model.rowCount), null);
});

void test("escapes callback kinds as well as module names", () => {
  const module = createDTestModule();
  module.callbacks[0]!.kind = "<callback>";
  const model = createDRuntimeModuleTableModel([module]);

  assert.match(model.rowAt(0)?.cells[model.columns.length - 1]?.html ?? "", /&lt;callback>/);
});

void test("omits reference tables for modules without references", () => {
  const module = createDTestModule();
  module.importedModules = [];
  module.localClasses = [];
  const pe = createBasePe();
  pe.dRuntime = { modules: [module], warnings: [] };
  const out: string[] = [];

  renderDRuntime(pe, out);

  assert.doesNotMatch(out.join(""), /pe-d-runtime-references/);
});
