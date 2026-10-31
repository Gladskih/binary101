import assert from "node:assert/strict";
import { test } from "node:test";
import { detectEmbeddedResources } from "../../../../analyzers/embedded-resources/detect.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { embeddedResourceFixture, minimalRcc, overwriteResource } from "../../../fixtures/embedded-resource-builders.js";
import type { ResourceSymbol } from "../../../../analyzers/embedded-resources/types.js";

const arraySymbols = (fixture = minimalRcc()): ResourceSymbol[] => [
  { name: "qt_resource_struct", scope: "qrc.cpp", offset: fixture.tree, size: fixture.nodeSize * 2 },
  { name: "qt_resource_name", scope: "qrc.cpp", offset: fixture.names, size: 8 },
  { name: "qt_resource_data", scope: "qrc.cpp", offset: fixture.data, size: fixture.bytes.length - fixture.data }
];

void test("finds both formats in ordinary sections at unaligned offsets and previews every bundle", async () => {
  const qt = embeddedResourceFixture("oracle-v3.rcc");
  const glib = embeddedResourceFixture("oracle.gresource");
  const bytes = new Uint8Array(1 + qt.length + glib.length);
  bytes.set(qt, 1);
  bytes.set(glib, 1 + qt.length);
  const result = await detectEmbeddedResources(new MockFile(bytes), [{ name: ".rodata", offset: 0, size: bytes.length }], []);
  assert.deepEqual(result?.issues, []);
  assert.deepEqual(result?.bundles.map(bundle => [bundle.offset, bundle.resource.format]),
    [[1, "Qt RCC"], [1 + qt.length, "GLib GResource"]]);
  assert.deepEqual(result?.bundles.map(bundle => bundle.issues), [[], []]);
  assert.deepEqual(result?.bundles.map(bundle => bundle.evidence), [
    ["qres signature and validated RCC tables"], ["GVDB signature, hash table, hierarchy and (uuay) values"]
  ]);
  assert.deepEqual(result?.bundles.map(bundle => bundle.resource.entries.find(entry =>
    entry.name === "plain.txt")?.preview?.textPreview), ["Qt and GLib resource oracle.", "Qt and GLib resource oracle."]);
});

void test("does not expose unconfirmed signatures or a section name as resources", async () => {
  const file = new MockFile(new TextEncoder().encode("qres GVariant raVGtnai"));
  assert.equal(await detectEmbeddedResources(file, [{ name: ".data", offset: 0, size: file.size }], []), null);
  assert.equal(await detectEmbeddedResources(file, [], []), null);
});

void test("reports corrupt explicitly named GResource sections without exposing resources", async () => {
  const file = new MockFile(new TextEncoder().encode("GVariant"));
  const result = await detectEmbeddedResources(file, [{ name: ".gresource.test", offset: 0, size: file.size }], []);
  assert.deepEqual(result?.bundles, []);
  assert.deepEqual(result?.issues, [".gresource.test: Resource structure is truncated or out of bounds"]);
  assert.equal(await detectEmbeddedResources(file, [{ name: ".rodata", offset: 0, size: file.size }], []), null);
});

void test("validates compiled array symbols and deduplicates symbols pointing into a qres package", async () => {
  const fixture = minimalRcc();
  const arrays = await detectEmbeddedResources(new MockFile(fixture.bytes), [], arraySymbols(fixture));
  assert.equal(arrays?.bundles.length, 1);
  assert.match(arrays!.bundles[0]!.evidence.join(), /symbols/);
  assert.deepEqual(arrays?.bundles[0]?.evidence,
    ["RCC array symbols in qrc.cpp", "Validated RCC tables and unique node layout"]);
  assert.equal(arrays?.bundles[0]?.resource.entries[1]?.preview?.textPreview, "hello");
  const duplicate = await detectEmbeddedResources(new MockFile(fixture.bytes),
    [{ name: ".data", offset: 0, size: fixture.bytes.length }], arraySymbols(fixture));
  assert.equal(duplicate?.bundles.length, 1);
  const twice = await detectEmbeddedResources(new MockFile(fixture.bytes), [], [
    ...arraySymbols(fixture), ...arraySymbols(fixture).map(symbol => ({ ...symbol, scope: "alias.cpp" }))
  ]);
  assert.equal(twice?.bundles.length, 1);
});

void test("reports invalid named arrays without claiming a resource", async () => {
  const fixture = minimalRcc();
  const corrupt = overwriteResource(fixture.bytes, fixture.tree + 4, 7, "be16");
  const result = await detectEmbeddedResources(new MockFile(corrupt), [], arraySymbols(fixture));
  assert.deepEqual(result?.bundles, []);
  assert.match(result!.issues.join(), /invalid or ambiguous/);
  assert.equal(result?.issues[0], `Qt array symbols at ${fixture.tree}: RCC array layout is invalid or ambiguous`);
});
