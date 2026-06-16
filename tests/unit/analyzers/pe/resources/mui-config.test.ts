"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMuiResourceConfiguration } from "../../../../../analyzers/pe/resources/mui-config.js";
import {
  buildMuiResourceConfigurationFixture,
  LANGUAGE_SPECIFIC_MUI_FILE_TYPE,
  MUI_RESOURCE_HEADER_SIZE,
  MUI_RESOURCE_VERSION
} from "../../../../fixtures/pe-mui-resource-config-fixture.js";

void test("parseMuiResourceConfiguration reads MUI resource lists and language metadata", () => {
  const parsed = parseMuiResourceConfiguration(buildMuiResourceConfigurationFixture());

  assert.ok(parsed);
  assert.equal(parsed.declaredSize, buildMuiResourceConfigurationFixture().byteLength);
  assert.equal(parsed?.version, MUI_RESOURCE_VERSION);
  assert.equal(parsed?.fileType, LANGUAGE_SPECIFIC_MUI_FILE_TYPE);
  assert.equal(parsed?.serviceChecksum, "0102030405060708090a0b0c0d0e0f10");
  assert.equal(parsed?.checksum, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  assert.deepEqual(parsed?.muiPaths, ["en-US\\fixture.dll.mui"]);
  assert.deepEqual(parsed?.mainTypeNames, ["MUI"]);
  assert.deepEqual(parsed?.mainTypeIds, [24]);
  assert.deepEqual(parsed?.muiTypeIds, [16]);
  assert.equal(parsed?.languageName, "en-US");
});

void test("parseMuiResourceConfiguration rejects truncated MUI resource data", () => {
  const truncated = buildMuiResourceConfigurationFixture().subarray(0, MUI_RESOURCE_HEADER_SIZE - 1);

  assert.equal(parseMuiResourceConfiguration(truncated), null);
});

void test("parseMuiResourceConfiguration rejects invalid range tables", () => {
  const malformed = buildMuiResourceConfigurationFixture();
  const view = new DataView(malformed.buffer, malformed.byteOffset, malformed.byteLength);
  view.setUint32(92, malformed.byteLength + 4, true);

  assert.equal(parseMuiResourceConfiguration(malformed), null);
});

void test("parseMuiResourceConfiguration rejects invalid signatures", () => {
  const malformed = buildMuiResourceConfigurationFixture();
  malformed[0] = malformed[0]! ^ 0xff;

  assert.equal(parseMuiResourceConfiguration(malformed), null);
});
