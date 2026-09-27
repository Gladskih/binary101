import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../../../../../analyzers/pe/resources/preview/index.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { buildMuiResourceConfigurationFixture } from "../../../../../fixtures/pe-mui-resource-config-fixture.js";
import {
  createPreviewLangEntry, createPreviewDetailGroup, createPreviewTree
} from "../../../../../helpers/pe-resource-preview-fixture.js";

for (const typeName of ["REGISTRY", "RGS", "registry"]) {
  void test(`named ${typeName} resources use ATL parsing with language metadata`, async () => {
    const data = new TextEncoder().encode(" HKCR { Key = s 'Test' }");
    const file = new MockFile(data);
    const result = await enrichResourcePreviews(file, createPreviewTree([
      createPreviewDetailGroup(typeName, 101, createPreviewLangEntry(1, data.length - 1, 65001))
    ]));
    const entry = result.detail[0]?.entries[0]?.langs[0];
    assert.equal(entry?.previewKind, "registry");
    assert.equal(entry?.registry?.roots[0]?.children[0]?.name, "Key");
  });
}

void test("ATL resource reads are bounded before loading a huge declared payload", async () => {
  const file = new MockFile(new TextEncoder().encode(" HKCR { Key }"));
  const reads: number[] = [];
  const original = file.readBytes.bind(file);
  file.readBytes = (offset, size) => { reads.push(size); return original(offset, size); };
  const result = await enrichResourcePreviews(file, createPreviewTree([
    createPreviewDetailGroup("REGISTRY", 101, createPreviewLangEntry(1, 0xffff_ffff, 65001))
  ]));
  assert.deepEqual(reads, [file.size - 1]);
  assert.match(result.detail[0]?.entries[0]?.langs[0]?.previewIssues?.join(" ") ?? "", /fewer bytes/);
});

void test("truncated and unmapped registry payloads surface warnings", async () => {
  const file = new MockFile(new TextEncoder().encode(" HKCR {"));
  const result = await enrichResourcePreviews(file, createPreviewTree([
    createPreviewDetailGroup("REGISTRY", 101, createPreviewLangEntry(1, 100, 65001)),
    createPreviewDetailGroup("REGISTRY", 102, createPreviewLangEntry(1, 100, 65001, 1033, null))
  ]));
  assert.match(result.detail[0]?.entries[0]?.langs[0]?.previewIssues?.join(" ") ?? "", /fewer bytes/);
  assert.match(result.detail[1]?.entries[0]?.langs[0]?.previewIssues?.join(" ") ?? "", /could not be mapped/);
});

void test("RCDATA entries explicitly named .rgs receive ATL analysis", async () => {
  const data = new TextEncoder().encode(" HKCU { Key }");
  const group = createPreviewDetailGroup("RCDATA", 101,
    createPreviewLangEntry(1, data.length - 1, 65001));
  group.entries[0]!.name = "registration.RGS";
  const result = await enrichResourcePreviews(new MockFile(data), createPreviewTree([group]));
  assert.equal(result.detail[0]?.entries[0]?.langs[0]?.registry?.roots[0]?.name, "HKCU");
});

void test("empty REGISTRY leaves are diagnosed rather than silently skipped", async () => {
  const result = await enrichResourcePreviews(new MockFile(new Uint8Array(2)), createPreviewTree([
    createPreviewDetailGroup("REGISTRY", 101, createPreviewLangEntry(1, 0))
  ]));
  assert.match(result.detail[0]?.entries[0]?.langs[0]?.previewIssues?.join(" ") ?? "", /empty/);
});

void test("REGISTRY resources with RVA and file offset zero are analyzed", async () => {
  const file = new MockFile(new TextEncoder().encode("HKCU { Zero }"));
  const result = await enrichResourcePreviews(file, createPreviewTree([
    createPreviewDetailGroup("REGISTRY", 1, createPreviewLangEntry(0, file.size, 65001))
  ]));
  assert.equal(result.detail[0]?.entries[0]?.langs[0]?.registry?.roots[0]?.children[0]?.name, "Zero");
});

void test("REGISTRY and RGS aliases reuse the payload parse across resource IDs and languages", async () => {
  const file = new MockFile(new TextEncoder().encode(" HKCU { Shared }"));
  const reads: number[] = [];
  const original = file.readBytes.bind(file);
  file.readBytes = (offset, size) => { reads.push(size); return original(offset, size); };
  const result = await enrichResourcePreviews(file, createPreviewTree([
    createPreviewDetailGroup("REGISTRY", 101, createPreviewLangEntry(1, file.size - 1, 65001, 1033)),
    createPreviewDetailGroup("RGS", 102, createPreviewLangEntry(1, file.size - 1, 65001, 1049))
  ]));
  assert.deepEqual(reads, [file.size - 1]);
  assert.strictEqual(result.detail[0]?.entries[0]?.langs[0]?.registry,
    result.detail[1]?.entries[0]?.langs[0]?.registry);
});

for (const [typeName, name] of [["RCDATA", null], ["RCDATA", "ordinary.bin"],
  ["RCDATA", "suffix.rgs.extra"], ["CUSTOM", "script.rgs"]] as const) {
  void test(`${typeName} entry ${name} remains outside ATL routing`, async () => {
    const file = new MockFile(new TextEncoder().encode(" HKCU { Key }"));
    const group = createPreviewDetailGroup(typeName, 1, createPreviewLangEntry(1, file.size - 1));
    group.entries[0]!.name = name;
    const result = await enrichResourcePreviews(file, createPreviewTree([group]));
    assert.equal(result.detail[0]?.entries[0]?.langs[0]?.registry, undefined);
  });
}

void test("unavailable generic payloads report their read issues without inventing a preview", async () => {
  const result = await enrichResourcePreviews(new MockFile(new Uint8Array(2)), createPreviewTree([
    createPreviewDetailGroup("CUSTOM", 1, createPreviewLangEntry(4, 2)),
    createPreviewDetailGroup("CUSTOM", 2, createPreviewLangEntry(1, 0)),
    createPreviewDetailGroup("CUSTOM", 3, createPreviewLangEntry(0, 1))
  ]));
  assert.deepEqual(result.detail[0]?.entries[0]?.langs[0]?.previewIssues,
    ["Resource preview read fewer bytes than the declared data size."]);
  assert.equal(result.detail[1]?.entries[0]?.langs[0]?.previewIssues, undefined);
  assert.equal(result.detail[2]?.entries[0]?.langs[0]?.previewIssues, undefined);
});

void test("MUI preview cache matches type, RVA and size independently", async () => {
  const config = buildMuiResourceConfigurationFixture();
  const bytes = new Uint8Array(config.length * 2 + 1);
  bytes.set(config, 1);
  const result = await enrichResourcePreviews(new MockFile(bytes), createPreviewTree([
    createPreviewDetailGroup("MUI", 1, createPreviewLangEntry(1, config.length)),
    createPreviewDetailGroup("MUI", 2, createPreviewLangEntry(1, 1)),
    createPreviewDetailGroup("MUI", 3, createPreviewLangEntry(1 + config.length, config.length)),
    createPreviewDetailGroup("REGISTRY", 4, createPreviewLangEntry(1, config.length)),
    createPreviewDetailGroup("CUSTOM", 5, createPreviewLangEntry(1, config.length))
  ]));
  assert.equal(result.detail[0]?.entries[0]?.langs[0]?.previewKind, "muiConfig");
  assert.equal(result.detail[1]?.entries[0]?.langs[0]?.muiConfig, undefined);
  assert.equal(result.detail[2]?.entries[0]?.langs[0]?.muiConfig, undefined);
  assert.ok(result.detail[3]?.entries[0]?.langs[0]?.registry);
  assert.equal(result.detail[4]?.entries[0]?.langs[0]?.muiConfig, undefined);
});

void test("unmapped MUI payloads do not require a cached MUI candidate", async () => {
  const result = await enrichResourcePreviews(new MockFile(new Uint8Array(2)), createPreviewTree([
    createPreviewDetailGroup("MUI", 1, createPreviewLangEntry(1, 1, 0, 1033, null))
  ]));
  assert.deepEqual(result.detail[0]?.entries[0]?.langs[0]?.previewIssues,
    ["Resource RVA could not be mapped to a file offset."]);
});
