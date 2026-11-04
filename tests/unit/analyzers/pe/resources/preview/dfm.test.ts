import assert from "node:assert/strict";
import { test } from "node:test";
import { addDfmPreview } from "../../../../../../analyzers/pe/resources/preview/dfm.js";
import { createDfmResource } from "../../../../../fixtures/pe-resource-advanced-payloads.js";

void test("reads a form, typed properties and nested components from TPF0", () => {
  const result = addDfmPreview(createDfmResource());

  assert.equal(result?.preview?.dfm?.className, "TForm");
  assert.equal(result?.preview?.dfm?.children[0]?.name, "Accept");
  assert.deepEqual(result?.preview?.dfm?.properties[0],
    { name: "ClientWidth", value: { kind: "number", value: "200" } });
  assert.equal(result?.issues, undefined);
});

void test("preserves readable properties when the child terminator is truncated", () => {
  const result = addDfmPreview(createDfmResource().subarray(0, -1));

  assert.equal(result?.preview?.dfm?.children[0]?.name, "Accept");
  assert.match(result?.issues?.join(" ") ?? "", /terminator/);
  assert.equal(addDfmPreview(new Uint8Array()), null);
});

void test("reports bytes after the root instead of discarding the anomaly", () => {
  const bytes = Uint8Array.from([...createDfmResource(), 1]);

  assert.match(addDfmPreview(bytes)?.issues?.join(" ") ?? "", /after the root/);
});

void test("preserves inline/inherited prefix flags and validates integer child positions", () => {
  const original = createDfmResource();
  const inline = Uint8Array.from([...original.subarray(0,4),0xf7,2,3,...original.subarray(4)]);
  const invalid = Uint8Array.from([...original.subarray(0,4),0xf2,5,...original.subarray(4)]);
  const reserved = Uint8Array.from([...original.subarray(0,4),0xf8,...original.subarray(4)]);

  assert.equal(addDfmPreview(inline)?.preview?.dfm?.flags,7);
  assert.equal(addDfmPreview(inline)?.preview?.dfm?.childPosition,"3");
  assert.match(addDfmPreview(invalid)?.issues?.join(" ") ?? "",/integer/);
  assert.match(addDfmPreview(reserved)?.issues?.join(" ") ?? "",/prefix flags/);
  assert.match(addDfmPreview(Uint8Array.of(84,80,70,48,0,0))?.issues?.join(" ") ?? "",/class is empty/);
});
