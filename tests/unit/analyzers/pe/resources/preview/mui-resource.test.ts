"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readMuiResource } from "../../../../../../analyzers/pe/resources/preview/mui-resource.js";
import type { ResourceDetailGroup } from "../../../../../../analyzers/pe/resources/preview/types.js";
import { buildMuiResourceConfigurationFixture } from "../../../../../fixtures/pe-mui-resource-config-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const lang = (
  dataRVA: number,
  dataFileOffset: number | null,
  size: number
): ResourceDetailGroup["entries"][number]["langs"][number] => ({
  lang: 1033,
  size,
  codePage: 0,
  dataRVA,
  dataFileOffset,
  reserved: 0
});

const detailGroup = (
  typeName: string,
  langs: ResourceDetailGroup["entries"][number]["langs"]
): ResourceDetailGroup => ({
  typeName,
  entries: [{ id: 1, name: null, langs }]
});

void test("readMuiResource ignores non-MUI resources even when they contain valid config bytes", async () => {
  const config = buildMuiResourceConfigurationFixture();
  const result = await readMuiResource(
    new MockFile(config),
    [detailGroup("MANIFEST", [lang(0x2000, 0, config.byteLength)])]
  );

  assert.equal(result, null);
});

void test("readMuiResource skips MUI entries without data RVA or size", async () => {
  const result = await readMuiResource(
    new MockFile(new Uint8Array(16)),
    [detailGroup("MUI", [lang(0, 0, 4), lang(0x2000, 0, 0)])]
  );

  assert.equal(result, null);
});

void test("readMuiResource returns the first valid configuration after malformed candidates", async () => {
  const malformed = new Uint8Array([0, 1, 2, 3]);
  const config = buildMuiResourceConfigurationFixture();
  const bytes = new Uint8Array(0x40 + malformed.byteLength + config.byteLength);
  bytes.set(malformed, 0);
  bytes.set(config, 0x40);

  const result = await readMuiResource(
    new MockFile(bytes),
    [detailGroup("MUI", [
      lang(0x2000, 0, malformed.byteLength),
      lang(0x2040, 0x40, config.byteLength)
    ])]
  );

  assert.equal(result?.dataRVA, 0x2040);
  assert.equal(result?.size, config.byteLength);
  assert.equal(result?.result.issues.length, 0);
  assert.ok(result?.result.configuration);
});

void test("readMuiResource keeps the first parsed MUI candidate when no valid config exists", async () => {
  const result = await readMuiResource(
    new MockFile(new Uint8Array([0, 1, 2, 3])),
    [detailGroup("MUI", [lang(0x2000, 0, 4)])]
  );

  assert.equal(result?.dataRVA, 0x2000);
  assert.equal(result?.result.configuration, null);
  assert.deepStrictEqual(result?.result.issues, [
    "MUI resource config signature is not fecdfecd."
  ]);
});

void test("readMuiResource reports mapped MUI entries whose payload cannot be read", async () => {
  const result = await readMuiResource(
    new MockFile(new Uint8Array(16)),
    [detailGroup("MUI", [lang(0x2000, null, 4)])]
  );

  assert.equal(result?.dataRVA, 0x2000);
  assert.equal(result?.result.configuration, null);
  assert.deepStrictEqual(result?.result.issues, [
    "Resource RVA could not be mapped to a file offset."
  ]);
});
