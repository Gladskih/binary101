import assert from "node:assert/strict";
import { test } from "node:test";
import { addRegistryPreview } from "../../../../analyzers/pe/resources/preview/registry.js";
import { renderPreviewCell, renderPreviewSummary } from "../../../../renderers/pe/resource-preview-cell.js";
import { renderRegistryPreview } from "../../../../renderers/pe/resource-preview-registry.js";
import { createRegistryTableModel } from "../../../../renderers/pe/resource-registry-table.js";
import { createPreviewLangEntry } from "../../../helpers/pe-resource-preview-fixture.js";

void test("registry UI displays operations, COM meaning, parameters and escaped source", () => {
  const preview = addRegistryPreview(new TextEncoder().encode(
    "HKCR { NoRemove CLSID { ForceRemove '%CLSID%' { InprocServer32 = s '%MODULE%' " +
    "{ val ThreadingModel = s 'Both' } } } Delete Obsolete '<script>' = s '<img>' }"
  ), "REGISTRY", 65001)?.preview;
  const entry = { ...createPreviewLangEntry(), ...preview };
  const html = renderPreviewCell(entry);
  assert.match(renderPreviewSummary(entry), /ATL registry/);
  assert.match(html, /COM class/);
  assert.match(html, /In-process COM server/);
  assert.match(html, /Keep key/);
  assert.match(html, /Delete subtree/);
  assert.match(html, /MODULE/);
  assert.match(html, /RGS source/);
  assert.match(html, /&lt;script/);
  assert.ok(!html.includes("<script>"));
  assert.equal(renderRegistryPreview(undefined), "");
});

void test("registry renderer formats every value type, empty names and source-free scripts", () => {
  const preview = addRegistryPreview(new TextEncoder().encode(
    "HKCU { Data { val '' = d '5' val Strings = m 'one\\0two' " +
    "val Bytes = b 'aabb' val Unknown = q '%VALUE%' } }"
  ), "REGISTRY", 65001)?.preview;
  const entry = { ...createPreviewLangEntry(), ...preview };
  delete entry.textPreview;
  const html = renderRegistryPreview(entry);
  assert.match(html, /5 \(0x00000005\)/);
  assert.match(html, /one/);
  assert.match(html, /aa bb/);
  assert.match(html, /unresolved type q/);
  assert.match(html, /\(Default\)/);
  assert.ok(!html.includes("<details>"));
  assert.ok(html.endsWith("</div>"));
  assert.equal(renderRegistryPreview(createPreviewLangEntry()), "");
  assert.match(renderRegistryPreview({ ...entry, registry: { roots: [] } }), /hives: none/);
  assert.match(renderRegistryPreview({ ...entry, textPreview: "HKCU { }", textEncoding: null }),
    /RGS source \(unknown\)/);
});

void test("registry rendering paginates all declarations and retains complete cells", () => {
  const preview = addRegistryPreview(new TextEncoder().encode(
    `HKCU { '${"x".repeat(5000)}' = s '${"y".repeat(5000)}' ${"Key ".repeat(1001)} }`
  ), "RGS", 65001)?.preview;
  assert.ok(preview?.registry);
  const model = createRegistryTableModel(preview.registry, "test-registry");
  const html = renderRegistryPreview({ ...createPreviewLangEntry(), ...preview }, model.id);
  assert.equal(model.rowCount, 1002);
  assert.match(html, /data-paged-sortable-table-root/);
  assert.ok(html.includes("x".repeat(5000)));
  assert.ok(html.includes("y".repeat(5000)));
  assert.ok(model.rowAt(1001));
  assert.equal(model.rowAt(1002), null);
  assert.equal((html.match(/<tr>/gu) ?? []).length, 51);
});

void test("protected ATL key names show that forced subtree deletion is skipped", () => {
  const preview = addRegistryPreview(new TextEncoder().encode(
    "HKCR { ForceRemove CLSID Delete Software }"
  ), "REGISTRY", 65001)?.preview;
  const html = renderRegistryPreview({ ...createPreviewLangEntry(), ...preview });
  assert.match(html, /Skip protected subtree deletion; create\/open key/);
  assert.match(html, /Skip protected subtree deletion<\/td>/);
});

void test("registry preview explains symbolic preprocessing, runtime effects and escaped source", () => {
  const preview = addRegistryPreview(new TextEncoder().encode(
    "HKCR { Key = s '%Module% %Other%' } HKCU { Other }"), "REGISTRY", 65001)?.preview;
  const html = renderRegistryPreview({ ...createPreviewLangEntry(), ...preview });
  assert.ok(html.includes("<p>ATL registry script. Root hives: HKCR, HKCU. "));
  assert.ok(html.includes("These are script declarations; registration depends on runtime parameters, permissions, "));
  assert.ok(html.includes("registry state and the 32/64-bit view. ATL can redirect HKCR to per-user Classes. "));
  assert.ok(html.includes("No registry changes are performed.</p>"));
  assert.ok(html.includes("<p>Runtime replacement parameters: <span class=\"mono\">%MODULE%, %OTHER%</span>. "));
  assert.ok(html.includes("Values remain symbolic; replacements may change the parsed structure. "));
  assert.ok(html.includes("%% represents a literal percent sign.</p>"));
  assert.ok(html.includes("<p class=\"smallNote\">ForceRemove/Delete respect ATL's protected key names, including "));
  assert.ok(html.includes("CLSID, Interface, TypeLib, AppID and Software.</p>"));
  assert.ok(html.includes("<details><summary>RGS source (utf-8)</summary><pre class=\"mono\">"));
  assert.ok(html.endsWith("</pre></details>"));
  assert.equal((html.match(/Runtime replacement parameters/gu) ?? []).length, 1);
  const plain = renderRegistryPreview({ ...createPreviewLangEntry(),
    ...addRegistryPreview(new TextEncoder().encode("HKCU { Key }"), "RGS", 65001)?.preview });
  assert.ok(!plain.includes("Runtime replacement parameters"));
  assert.ok(plain.includes("No registry changes are performed.</p><p class=\"smallNote\">ForceRemove/Delete"));
  assert.match(plain, /data-sort-state-key="pe-registry"/);
});
