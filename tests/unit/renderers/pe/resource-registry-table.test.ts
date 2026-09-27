import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRegistryScript } from "../../../../analyzers/pe/resources/preview/registry-parser.js";
import { createRegistryTableModel } from "../../../../renderers/pe/resource-registry-table.js";
import { createResourceDetailTableModel, getPeResourceTableModel } from "../../../../renderers/pe/resources.js";
import { createPreviewLangEntry, createPreviewDetailGroup } from "../../../helpers/pe-resource-preview-fixture.js";

// UI policy is 50 rows/page (resources.ts); 51 exercises the next page.
// Depth 10000 is a stack-safety stress size, not a format limit; 10001 includes the leaf/root.
// Expected DWORD hex width = 32 bits / 4 bits per digit = 8:
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
// https://www.rfc-editor.org/rfc/rfc4648.html#section-8
void test("registry table exposes canonical columns and complete row/sort values", () => {
  const model = createRegistryTableModel(parseRegistryScript("HKCU { Key { val Name = d '5' } }", []), "table-id");
  assert.equal(model.id, "table-id");
  assert.equal(model.pageSize, 50);
  assert.equal(model.rowCount, 2);
  assert.equal(model.tableClassName, "peResourceNestedTable");
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.sortValue), ["HKEY_CURRENT_USER\\Key", "key",
    "—", "—", "—", "—", "Create/open key", "Remove key after children, if no subkeys", "1:8"]);
  assert.deepEqual(model.columns.map(column => column.label), ["Key path", "Directive", "Value name",
    "Type", "Data / template", "COM meaning", "Register", "Unregister", "Line:column"]);
  assert.deepEqual(model.rowAt(1)?.cells.map(cell => cell.sortValue), ["HKEY_CURRENT_USER\\Key", "val",
    "Name", "REG_DWORD", "5 (0x00000005)", "—", "Set named value", "Delete named value", "1:14"]);
  assert.deepEqual(Array.from({ length: 9 }, (_, column) => model.sortValueAt(1, column)),
    model.rowAt(1)?.cells.map(cell => cell.sortValue));
  assert.equal(model.rowAt(-1), null);
  assert.equal(model.rowAt(2), null);
  assert.equal(model.sortValueAt(-1, 0), "");
  assert.equal(model.sortValueAt(2, 0), "");
  assert.equal(model.sortValueAt(0, 9), "");
});

void test("parent index preserves depth-first paths, sibling hives and escaping", () => {
  const script = parseRegistryScript("Unknown { '<key>' { val '<name>' = s '<value>' } Sibling } " +
    "HKCR { CLSID { '%ID%' } }", []);
  const model = createRegistryTableModel(script, "first");
  assert.equal(model.rowCount, 5);
  assert.equal(model.sortValueAt(0, 0), "Unknown\\<key>");
  assert.equal(model.sortValueAt(1, 0), "Unknown\\<key>");
  assert.equal(model.sortValueAt(2, 0), "Unknown\\Sibling");
  assert.equal(model.sortValueAt(3, 0), "HKEY_CLASSES_ROOT\\CLSID");
  assert.equal(model.sortValueAt(4, 5), "COM class (CLSID)");
  assert.equal(model.rowAt(1)?.cells[2]?.html, "&lt;name>");
  assert.equal(model.rowAt(1)?.cells[4]?.html, "&lt;value>");
  assert.equal(createRegistryTableModel(script, "second").sortValueAt(2, 0), "Unknown\\Sibling");
  assert.equal(createRegistryTableModel({ roots: [] }, "empty").rowCount, 0);
});

void test("deep tree indexing and on-demand full paths avoid the JavaScript call stack", () => {
  const model = createRegistryTableModel(parseRegistryScript("HKCU { " + "Key { ".repeat(10000) +
    "Leaf " + "} ".repeat(10001), []), "deep");
  assert.equal(model.rowCount, 10001);
  assert.equal(model.sortValueAt(10000, 0), "HKEY_CURRENT_USER\\" + "Key\\".repeat(10000) + "Leaf");
});

for (const name of ["APPID", "CLSID", "COMPONENT CATEGORIES", "FILETYPE", "INTERFACE", "HARDWARE",
  "MIME", "SAM", "SECURITY", "SYSTEM", "SOFTWARE", "TYPELIB"]) {
  void test(`ATL protects forced deletion of '${name}' at arbitrary depths and mixed case`, () => {
    const model = createRegistryTableModel(parseRegistryScript(
      `HKCU { Outer { ForceRemove '${name.toLowerCase()}' Delete '${name.toLowerCase()}' } }`, []), "table");
    assert.equal(model.sortValueAt(1, 6), "Skip protected subtree deletion; create/open key");
    assert.equal(model.sortValueAt(1, 7), "Remove key after children, if no subkeys");
    assert.equal(model.sortValueAt(2, 6), "Skip protected subtree deletion");
    assert.equal(model.sortValueAt(2, 7), "Remove key after children, if no subkeys");
  });
}

void test("every directive displays exact Register/Unregister actions and default values", () => {
  const model = createRegistryTableModel(parseRegistryScript(
    "HKCU { Key NoRemove Shared ForceRemove Old Delete Removed Assigned = s 'value' " +
    "val '' = s 'default' }", []), "actions");
  assert.deepEqual(Array.from({ length: 6 }, (_, index) =>
    [model.sortValueAt(index, 2), model.sortValueAt(index, 6), model.sortValueAt(index, 7)]), [
    ["—", "Create/open key", "Remove key after children, if no subkeys"],
    ["—", "Create/open key", "Keep key; process children"],
    ["—", "Delete subtree; create/open key", "Remove key after children, if no subkeys"],
    ["—", "Delete subtree", "Remove key after children, if no subkeys"],
    ["(Default)", "Create/open key", "Remove key after children, if no subkeys"],
    ["(Default)", "Set named value", "Delete named value"]
  ]);
});

void test("all registry value types display complete data with readable separators", () => {
  const model = createRegistryTableModel(parseRegistryScript(
    "HKCU { Text = s 'hello' Multi = m 'one\\0two' Bytes = b '00aaff' Unknown = q '%X%' }", []), "types");
  assert.deepEqual(Array.from({ length: 4 }, (_, index) =>
    [model.sortValueAt(index, 3), model.sortValueAt(index, 4)]), [
    ["REG_SZ", "hello"], ["REG_MULTI_SZ", '"one"; "two"'],
    ["REG_BINARY", "00 aa ff"], ["unresolved", "%X% (unresolved type q)"]
  ]);
});

void test("recreating a table model reuses its tree index instead of walking the tree again", () => {
  const script = parseRegistryScript("HKCU { Key }", []);
  let visits = 0;
  const children = script.roots[0]!.children;
  Object.defineProperty(script.roots[0], "children", { get: () => { visits += 1; return children; } });
  assert.equal(createRegistryTableModel(script, "first").rowCount, 1);
  const previousVisits = visits;
  assert.equal(createRegistryTableModel(script, "second").rowCount, 1);
  assert.equal(visits, previousVisits);
});

void test("resource table routing distinguishes registry previews that share a payload RVA", () => {
  const registry = parseRegistryScript("HKCU { " + "Key ".repeat(51) + "}", []);
  const entry = { ...createPreviewLangEntry(1, 2), previewKind: "registry" as const, registry };
  const group = createPreviewDetailGroup("REGISTRY", 1, entry);
  group.entries.push({ id: 2, name: null, langs: [entry] });
  const resources = { top: [], detail: [group] };
  assert.equal(getPeResourceTableModel(resources, "pe-registry-0-0")?.rowCount, 51);
  assert.equal(getPeResourceTableModel(resources, "pe-registry-0-1")?.id, "pe-registry-0-1");
  assert.equal(getPeResourceTableModel(resources, "pe-registry-0-2"), null);
  assert.equal(getPeResourceTableModel(resources, "pe-registry-1-0"), null);
  assert.equal(getPeResourceTableModel(undefined, "pe-registry-0-0"), null);
  const missingDetail = { top: [], detail: [group] };
  Reflect.deleteProperty(missingDetail, "detail");
  assert.equal(getPeResourceTableModel(missingDetail, "pe-registry-0-0"), null);
  assert.equal(getPeResourceTableModel(resources, "pe-registry-0-0-extra"), null);
  assert.equal(getPeResourceTableModel(resources, "extra-pe-registry-0-0"), null);
  assert.match(createResourceDetailTableModel(group, 0).rowAt(1)?.additionalRowsHtml ?? "",
    /data-paged-sortable-table-id="pe-registry-0-1"/);
});

void test("registry table IDs accept multi-digit group and language-row indexes", () => {
  const entry = { ...createPreviewLangEntry(), registry: parseRegistryScript("HKCU { Last }", []) };
  const group = createPreviewDetailGroup("REGISTRY", 1, entry);
  group.entries = Array.from({ length: 20 }, (_, index) => ({ id: index, name: null, langs: [entry] }));
  const resources = { top: [], detail: Array.from({ length: 15 }, () => group) };
  assert.equal(getPeResourceTableModel(resources, "pe-registry-12-15")?.sortValueAt(0, 0),
    "HKEY_CURRENT_USER\\Last");
});

for (const previewKind of ["dialog", "image"] as const) {
  void test(`${previewKind} resources retain their wide preview layout alongside registry tables`, () => {
    const entry = { ...createPreviewLangEntry(), previewKind };
    const row = createResourceDetailTableModel(createPreviewDetailGroup("CUSTOM", 1, entry), 0).rowAt(0);
    assert.equal(row?.className, "peResourcePreviewMetaRow");
    assert.match(row?.additionalRowsHtml ?? "", /colspan="5"/);
  });
}

void test("resources without a decoded preview use the normal metadata row", () => {
  const row = createResourceDetailTableModel(createPreviewDetailGroup(
    "CUSTOM", 1, createPreviewLangEntry()), 0).rowAt(0);
  assert.equal(row?.className, undefined);
  assert.equal(row?.additionalRowsHtml, undefined);
});
