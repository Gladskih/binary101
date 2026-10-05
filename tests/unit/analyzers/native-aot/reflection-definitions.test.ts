import assert from "node:assert/strict";
import { test } from "node:test";
import { parseNativeAotReflectionMetadata } from
  "../../../../analyzers/native-aot/reflection-metadata.js";
import { createNativeFormatMetadataFixture } from
  "../../../helpers/native-format-metadata-fixture.js";

void test("retains type declarations and accepts the UInt16 version boundary", () => {
  const parsed = parseNativeAotReflectionMetadata(createNativeFormatMetadataFixture(65535));

  assert.equal(parsed.scopes[0]?.version.major, 65535);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.definition, {
    flags: 1, size: 0, packingSize: 0, baseType: "", interfaces: [], genericParameters: [],
    properties: [], events: []
  });
  assert.equal(parsed.warnings, undefined);
});

void test("rejects scope version overflow instead of wrapping the component", () => {
  const parsed = parseNativeAotReflectionMetadata(createNativeFormatMetadataFixture(65536));

  assert.deepEqual(parsed.scopes, []);
  assert.match(parsed.warnings?.join(" ") ?? "", /Version component exceeds UInt16/);
});
