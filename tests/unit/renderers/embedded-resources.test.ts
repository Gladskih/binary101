import assert from "node:assert/strict";
import { test } from "node:test";
import { detectEmbeddedResources } from "../../../analyzers/embedded-resources/detect.js";
import { createEmbeddedResourceTableModel, getEmbeddedResourceTableModel, renderEmbeddedResources }
  from "../../../renderers/embedded-resources.js";
import { minimalRcc } from "../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../helpers/mock-file.js";
import { getPePagedTableModel } from "../../../renderers/pe/paged-tables.js";
import { renderPe } from "../../../renderers/pe/index.js";
import { renderElf } from "../../../renderers/elf/index.js";
import { getElfPagedTableModel } from "../../../renderers/elf/paged-tables.js";
import { getElfLazySections } from "../../../renderers/elf/lazy-sections.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { parseElf } from "../../../analyzers/elf/index.js";
import { embeddedResourceFixture } from "../../fixtures/embedded-resource-builders.js";

void test("renders shared metadata, hierarchy, preview and download using escaped values", async () => {
  const bytes = minimalRcc(2).bytes;
  const result = await detectEmbeddedResources(new MockFile(bytes), [{ name: ".data", offset: 0, size: bytes.length }], []);
  assert.ok(result);
  result.issues.push("<unavailable>");
  result.bundles[0]!.issues.push("<content>");
  result.bundles[0]!.resource.entries[1]!.name = "<a>";
  const html = renderEmbeddedResources(result);
  assert.match(html, /Qt \/ GLib embedded resources/);
  assert.match(html, /&lt;a&gt;/);
  assert.match(html, /&lt;unavailable&gt;/);
  assert.match(html, /&lt;content&gt;/);
  assert.match(html, /hello/);
  assert.match(html, /data-embedded-resource-entry="1"/);
  assert.match(html, /timestamp/);
  const model = createEmbeddedResourceTableModel(result, 0);
  assert.equal(model.rowCount, 2);
  assert.equal(model.rowAt(2), null);
  assert.equal(model.sortValueAt(2, 0), "");
  assert.equal(model.sortValueAt(1, 100), "");
  assert.equal(model.sortValueAt(1, 1), "<a>");
  assert.equal(model.sortValueAt(0, 0), "0");
  assert.equal(model.sortValueAt(0, 2), "");
  assert.equal(model.sortValueAt(1, 2), "0");
  assert.equal(model.sortValueAt(1, 4), String(result.bundles[0]!.resource.entries[1]!.payload!.offset));
  assert.equal(model.sortValueAt(1, 5), "5");
  assert.equal(model.sortValueAt(1, 6), "5");
  assert.match(model.rowAt(0)!.cells[1]!.html, /\//);
  assert.match(model.rowAt(0)!.cells[3]!.html, /Directory/);
  assert.ok(getEmbeddedResourceTableModel(result, "embedded-resources-0"));
  assert.equal(getEmbeddedResourceTableModel(result, "embedded-resources-1"), null);
  assert.equal(getEmbeddedResourceTableModel(result, "other-0"), null);
  assert.equal(getEmbeddedResourceTableModel(undefined, "embedded-resources-0"), null);
  assert.equal(renderEmbeddedResources(undefined), "");
});

void test("preserves literal entity-looking text in resource names and diagnostics", async () => {
  const bytes = minimalRcc().bytes;
  const result = await detectEmbeddedResources(new MockFile(bytes), [{ name: ".data", offset: 0, size: bytes.length }], []);
  assert.ok(result);
  result.bundles[0]!.resource.entries[1]!.name = "&lt;file&gt;";
  result.issues.push("&diagnostic;");
  const html = renderEmbeddedResources(result);
  assert.match(html, /&amp;lt;file&amp;gt;/);
  assert.match(html, /&amp;diagnostic;/);
});

void test("integrates common resource tables with PE, ELF and lazy ELF table resolvers", async () => {
  const elf = await parseElf(new MockFile(embeddedResourceFixture("qt-glib.so")));
  assert.ok(elf?.embeddedResources);
  const pe = { ...createBasePe(), embeddedResources: elf.embeddedResources };
  assert.match(renderPe(pe), /Qt \/ GLib embedded resources/);
  assert.match(renderElf(elf), /Qt \/ GLib embedded resources/);
  assert.ok(getPePagedTableModel(pe, "embedded-resources-0"));
  assert.ok(getElfPagedTableModel(elf, "embedded-resources-0"));
  assert.match(getElfLazySections(elf).find(section => section.key === "embedded-resources")!.render(), /GLib GResource/);
});
