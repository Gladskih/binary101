"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { createNativeFormatTraversalFixture } from
  "../../../helpers/native-format-traversal-fixture.js";
import { parseNativeAotReflectionMetadata } from
  "../../../../analyzers/native-aot/reflection-metadata.js";
import {
  createNativeFormatFieldFixture,
  patchNativeFormatFieldSlot
} from "../../../helpers/native-format-field-fixture.js";
import {
  createNativeFormatMetadataFixture,
  createNativeFormatMetadataWithRepeatedMembersFixture,
  createNativeFormatMetadataWithRepeatedScopesFixture,
  createNativeFormatMetadataWithTypeCycleFixture,
  createNativeFormatMetadataWithDuplicateReferencesFixture,
  createNativeFormatMetadataWithNamespaceCycleFixture
} from
  "../../../helpers/native-format-metadata-fixture.js";

const corruptString = (value: string, metadata = createNativeFormatMetadataFixture()): Uint8Array => {
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
      types: [{ namespace: "Demo", name: "Program", methods: ["Main"],
        fields: ["Count", "<Name>k__BackingField"] }, {
        namespace: "Demo",
        name: "Program+Nested",
        methods: ["Work"],
        fields: ["Value"]
      }, {
        namespace: "Demo.Inner",
        name: "Worker",
        methods: ["Run"],
        fields: []
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

void test("parseNativeAotReflectionMetadata rejects oversized blobs and truncated root lists", () => {
  // NativeFormat handles have a 25-bit offset field, so a 32 MiB blob is the hard boundary.
  const oversized = new Uint8Array(0x0200_0001);
  // NativePrimitiveDecoder's one-byte form declares one scope, but its handle is missing.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
  const truncatedScopes = Uint8Array.from([0xfd, 0xdf, 0xad, 0xde, 0x02]);

  const oversizedResult = parseNativeAotReflectionMetadata(oversized);
  const boundaryResult = parseNativeAotReflectionMetadata(oversized.subarray(0, 0x0200_0000));
  const countResult = parseNativeAotReflectionMetadata(truncatedScopes);

  assert.match(oversizedResult.warnings?.[0] ?? "", /32 MiB/);
  assert.match(boundaryResult.warnings?.[0] ?? "", /signature/i);
  assert.match(countResult.warnings?.[0] ?? "", /outside the metadata/i);
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

void test("reflection preserves sibling fields, methods and types after an invalid field name", () => {
  const parsed = parseNativeAotReflectionMetadata(corruptString("Count"));

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, ["<Name>k__BackingField"]);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.methods, ["Main"]);
  assert.deepEqual(parsed.scopes[0]?.types[1]?.fields, ["Value"]);
  assert.match(parsed.warnings?.[0] ?? "", /field.*UTF-8/);
});

void test("reflection reuses decoded members while preserving repeated list entries", context => {
  const metadata = createNativeFormatMetadataWithRepeatedMembersFixture(2);
  const reads = context.mock.method(NativeFormatReader.prototype, "string");

  const parsed = parseNativeAotReflectionMetadata(metadata);

  assert.equal(parsed.warnings, undefined);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.methods, ["Main", "Main"]);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, ["Count", "Count"]);
  assert.deepEqual(parsed.scopes[0]?.types[1]?.methods, ["Work"]);
  assert.deepEqual(parsed.scopes[0]?.types[1]?.fields, ["Value"]);
  assert.equal(reads.mock.calls.filter(call => call.result === "Main").length, 1);
  assert.equal(reads.mock.calls.filter(call => call.result === "Count").length, 1);
});

void test("reflection skips nil field slots and continues to other types", () => {
  const { bytes, type } = createNativeFormatFieldFixture();
  patchNativeFormatFieldSlot(bytes, type.fieldsOffset + 1, 0);

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types.map(type => type.fields), [
    ["<Name>k__BackingField"], ["Value"], []
  ]);
  assert.equal(parsed.warnings, undefined);
});

void test("reflection preserves types and methods when a field list is malformed", () => {
  const { bytes, type } = createNativeFormatFieldFixture();
  bytes[type.fieldsOffset] = 0xff; // Invalid compressed-integer prefix.

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, []);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.methods, ["Main"]);
  assert.deepEqual(parsed.scopes[0]?.types[1]?.fields, ["Value"]);
  assert.match(parsed.warnings?.[0] ?? "", /field list.*compressed integer/);
});

void test("reflection rejects a field list with an out-of-bounds handle", () => {
  const { bytes, type } = createNativeFormatFieldFixture();
  patchNativeFormatFieldSlot(bytes, type.fieldsOffset + 1, bytes.length);

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, []);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.methods, ["Main"]);
  assert.match(parsed.warnings?.[0] ?? "", /field list.*outside the metadata/);
});

void test("reflection contains a truncated field record", () => {
  const { bytes, type } = createNativeFormatFieldFixture();
  patchNativeFormatFieldSlot(bytes, type.fieldsOffset + 1, bytes.length - 1);

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, ["<Name>k__BackingField"]);
  assert.match(parsed.warnings?.[0] ?? "", /field.*outside the metadata/);
});

void test("reflection caches repeated field names within one parse", context => {
  const { bytes, type, fields, reader } = createNativeFormatFieldFixture();
  const nameHandle = reader.handle(fields[0]!.offset + 1, [0x1a]).value;
  // The second reserved five-byte handle follows the one-byte count and first handle.
  patchNativeFormatFieldSlot(bytes, type.fieldsOffset + 6, fields[0]!.offset);
  const stringReads = context.mock.method(NativeFormatReader.prototype, "string");

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, ["Count", "Count"]);
  assert.equal(stringReads.mock.calls.filter(call =>
    call.arguments[0].offset === nameHandle.offset).length, 1);
  assert.equal(parsed.warnings, undefined);
});

void test("reflection caches failed field records and reports them once", context => {
  const { bytes, type, fields } = createNativeFormatFieldFixture();
  patchNativeFormatFieldSlot(bytes, type.fieldsOffset + 6, fields[0]!.offset);
  bytes[fields[0]!.offset] = 0xff;
  const reads = context.mock.method(NativeFormatReader.prototype, "unsigned");

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, []);
  assert.equal(parsed.warnings?.length, 1);
  assert.match(parsed.warnings?.[0] ?? "", /field.*compressed integer/);
  assert.equal(reads.mock.calls.filter(call => call.arguments[0] === fields[0]!.offset).length, 1);
});

void test("reflection stops at the declared field count without reading the unused type tail", () => {
  const { bytes, type } = createNativeFormatFieldFixture();
  // One count byte + two reserved five-byte handles; the property collection is not consumed.
  bytes[type.fieldsOffset + 11] = 0xff;

  const parsed = parseNativeAotReflectionMetadata(bytes);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, ["Count", "<Name>k__BackingField"]);
  assert.equal(parsed.warnings, undefined);
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

void test("reflection preserves declaring names and depth-first order through nested types", () => {
  const metadata = createNativeFormatTraversalFixture("type", ["Container", "Leaf"]);

  const parsed = parseNativeAotReflectionMetadata(metadata);

  assert.equal(parsed.warnings, undefined);
  assert.deepEqual(parsed.scopes[0]?.types.map(type => type.name), [
    "Program", "Program+Container", "Program+Container+Leaf",
    "Program+Container+Leaf+Nested", "Worker"
  ]);
  assert.deepEqual(parsed.scopes[0]?.types.at(-2)?.methods, ["Work"]);
  assert.deepEqual(parsed.scopes[0]?.types.at(-1)?.methods, ["Run"]);
});

void test("reflection inherits the parent namespace through unnamed namespace records", () => {
  const metadata = createNativeFormatTraversalFixture("namespace", ["Branch", ""]);

  const parsed = parseNativeAotReflectionMetadata(metadata);

  assert.equal(parsed.warnings, undefined);
  assert.deepEqual(parsed.scopes[0]?.types.map(type => type.name), [
    "Program", "Program+Nested", "Worker"
  ]);
  assert.equal(parsed.scopes[0]?.types.at(-1)?.namespace, "Demo.Branch.Inner");
});

void test("reflection decodes repeated scopes once", context => {
  const metadata = createNativeFormatMetadataWithRepeatedScopesFixture(2);
  const reads = context.mock.method(NativeFormatReader.prototype, "string");

  const parsed = parseNativeAotReflectionMetadata(metadata);

  assert.equal(parsed.warnings, undefined);
  assert.equal(parsed.scopes.length, 1);
  assert.equal(reads.mock.calls.filter(call => call.result === "HelloCSharp").length, 1);
});

void test("reflection terminates on a nested type cycle without losing sibling namespaces", () => {
  const parsed = parseNativeAotReflectionMetadata(createNativeFormatMetadataWithTypeCycleFixture());

  assert.equal(parsed.warnings, undefined);
  assert.deepEqual(parsed.scopes[0]?.types.map(type => type.name), ["Program", "Worker"]);
});

void test("reflection decodes repeated malformed methods once and preserves other members", context => {
  const metadata = corruptString("Main", createNativeFormatMetadataWithRepeatedMembersFixture(2));
  const reads = context.mock.method(NativeFormatReader.prototype, "string");

  const parsed = parseNativeAotReflectionMetadata(metadata);

  assert.deepEqual(parsed.scopes[0]?.types[0]?.methods, []);
  assert.deepEqual(parsed.scopes[0]?.types[0]?.fields, ["Count", "Count"]);
  assert.deepEqual(parsed.scopes[0]?.types[1]?.methods, ["Work"]);
  assert.equal(parsed.warnings?.length, 1);
  assert.match(parsed.warnings?.[0] ?? "", /method.*UTF-8/);
  assert.equal(reads.mock.calls.filter(call => call.error !== undefined).length, 1);
});
