"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseNativeAotReflectionMetadata } from
  "../../../../analyzers/native-aot/reflection-metadata.js";
import {
  createNativeFormatMetadataFixture,
  createNativeFormatMetadataWithDuplicateReferencesFixture,
  createNativeFormatMetadataWithNamespaceCycleFixture
} from
  "../../../helpers/native-format-metadata-fixture.js";

const corruptString = (value: string): Uint8Array => {
  const metadata = createNativeFormatMetadataFixture();
  const needle = new TextEncoder().encode(value);
  const offset = metadata.findIndex((_, index) =>
    needle.every((byte, relative) => metadata[index + relative] === byte));
  if (offset < 0) throw new Error(`Fixture string not found: ${value}`);
  metadata[offset] = 0xff;
  return metadata;
};

void test("parseNativeAotReflectionMetadata reads scopes, nested types, and method names", () => {
  const parsed = parseNativeAotReflectionMetadata(createNativeFormatMetadataFixture());

  assert.deepEqual(parsed, {
    scopes: [{
      name: "HelloCSharp",
      moduleName: "HelloCSharp.dll",
      version: { major: 1, minor: 2, build: 3, revision: 4 },
      types: [{ namespace: "Demo", name: "Program", methods: ["Main"] }, {
        namespace: "Demo",
        name: "Program+Nested",
        methods: ["Work"]
      }, {
        namespace: "Demo.Inner",
        name: "Worker",
        methods: ["Run"]
      }]
    }]
  });
});

void test("parseNativeAotReflectionMetadata reports malformed and truncated input", () => {
  const wrongSignature = createNativeFormatMetadataFixture();
  wrongSignature[0] = wrongSignature[0]! ^ 1;

  const invalid = parseNativeAotReflectionMetadata(wrongSignature);
  const truncated = parseNativeAotReflectionMetadata(
    createNativeFormatMetadataFixture().subarray(0, 9)
  );

  assert.deepEqual(invalid.scopes, []);
  assert.match(invalid.warnings?.[0] ?? "", /signature/i);
  assert.deepEqual(truncated.scopes, []);
  assert.match(truncated.warnings?.[0] ?? "", /truncated|range/i);
});

void test("parseNativeAotReflectionMetadata accepts an empty graph and rejects empty input", () => {
  // A signature-only blob has no root handles and is the smallest valid NativeFormat container.
  const emptyGraph = Uint8Array.from([0xfd, 0xdf, 0xad, 0xde, 0]);

  assert.deepEqual(parseNativeAotReflectionMetadata(emptyGraph), { scopes: [] });
  assert.match(parseNativeAotReflectionMetadata(new Uint8Array()).warnings?.[0] ?? "", /signature/i);
  assert.match(
    parseNativeAotReflectionMetadata(emptyGraph.subarray(0, 4)).warnings?.[0] ?? "",
    /root/i
  );
});

void test("parseNativeAotReflectionMetadata enforces root and metadata limits", () => {
  // NativeFormat handles have a 25-bit offset field, so a 32 MiB blob is the hard boundary.
  const oversized = new Uint8Array(0x0200_0001);
  // NativePrimitiveDecoder's five-byte form encodes 4097, one above our scope safety cap.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
  const excessiveScopes = Uint8Array.from([
    0xfd, 0xdf, 0xad, 0xde,
    0x0f, 1, 16, 0, 0
  ]);

  const oversizedResult = parseNativeAotReflectionMetadata(oversized);
  const boundaryResult = parseNativeAotReflectionMetadata(oversized.subarray(0, 0x0200_0000));
  const countResult = parseNativeAotReflectionMetadata(excessiveScopes);

  assert.match(oversizedResult.warnings?.[0] ?? "", /32 MiB/);
  assert.match(boundaryResult.warnings?.[0] ?? "", /signature/i);
  assert.match(countResult.warnings?.[0] ?? "", /safety limit/i);
});

void test("parseNativeAotReflectionMetadata contains malformed graph records", () => {
  const method = parseNativeAotReflectionMetadata(corruptString("Main"));
  const type = parseNativeAotReflectionMetadata(corruptString("Program"));
  const namespace = parseNativeAotReflectionMetadata(corruptString("Demo"));
  const scope = parseNativeAotReflectionMetadata(corruptString("HelloCSharp"));

  assert.match(method.warnings?.[0] ?? "", /method/i);
  assert.deepEqual(method.scopes[0]?.types[0]?.methods, []);
  assert.match(type.warnings?.[0] ?? "", /type/i);
  assert.match(namespace.warnings?.[0] ?? "", /namespace/i);
  assert.match(scope.warnings?.[0] ?? "", /scope/i);
  assert.deepEqual(scope.scopes, []);
});

void test("parseNativeAotReflectionMetadata enforces graph traversal limits", () => {
  const metadata = createNativeFormatMetadataFixture();
  const baseLimits = { namespaces: 10, types: 10, methods: 10, namespaceDepth: 10 };

  const methods = parseNativeAotReflectionMetadata(metadata, { ...baseLimits, methods: 1 });
  const types = parseNativeAotReflectionMetadata(metadata, { ...baseLimits, types: 1 });
  const depth = parseNativeAotReflectionMetadata(metadata, { ...baseLimits, namespaceDepth: 1 });
  const namespaces = parseNativeAotReflectionMetadata(metadata, { ...baseLimits, namespaces: 1 });

  assert.match(methods.warnings?.[0] ?? "", /Method count/);
  assert.deepEqual(methods.scopes[0]?.types.map(type => type.methods), [["Main"], [], []]);
  assert.equal(methods.warnings?.length, 1);
  assert.match(types.warnings?.[0] ?? "", /Type count/);
  assert.deepEqual(types.scopes[0]?.types.map(type => type.name), ["Program"]);
  assert.equal(types.warnings?.length, 1);
  assert.match(depth.warnings?.[0] ?? "", /Namespace traversal/);
  assert.deepEqual(depth.scopes[0]?.types.map(type => type.name), ["Program", "Program+Nested"]);
  assert.match(namespaces.warnings?.[0] ?? "", /Namespace traversal/);
  assert.deepEqual(namespaces.scopes[0]?.types, []);
});

void test("parseNativeAotReflectionMetadata ignores duplicate graph references", () => {
  const parsed = parseNativeAotReflectionMetadata(
    createNativeFormatMetadataWithDuplicateReferencesFixture()
  );

  assert.deepEqual(parsed.scopes[0]?.types.map(type => type.name), [
    "Program",
    "Program+Nested",
    "Worker"
  ]);
});

void test("parseNativeAotReflectionMetadata contains namespace cycles", () => {
  const parsed = parseNativeAotReflectionMetadata(
    createNativeFormatMetadataWithNamespaceCycleFixture()
  );

  assert.equal(parsed.warnings, undefined);
  assert.deepEqual(parsed.scopes[0]?.types.map(type => type.name), [
    "Program",
    "Program+Nested",
    "Worker"
  ]);
});
