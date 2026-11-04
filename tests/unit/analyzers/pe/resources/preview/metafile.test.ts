import assert from "node:assert/strict";
import { test } from "node:test";
import { addMetafilePreview } from "../../../../../../analyzers/pe/resources/preview/metafile.js";
import { createEmfResource, createEmfRecord, createWmfResource, createPlaceableWmfResource } from
  "../../../../../fixtures/pe-resource-advanced-payloads.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

void test("recognizes bounded EMF and WMF records and their geometric primitives", () => {
  const emf = expectDefined(addMetafilePreview(createEmfResource())?.preview?.vector);
  const wmf = expectDefined(addMetafilePreview(createWmfResource())?.preview?.vector);
  const placeable = expectDefined(addMetafilePreview(createPlaceableWmfResource())?.preview?.vector);

  assert.equal(emf.format, "EMF");
  assert.equal(emf.nodes[0]?.tag, "rect");
  assert.equal(emf.records?.length, 3);
  assert.equal(wmf.format, "WMF");
  assert.deepEqual(placeable.bounds, { x: 0, y: 0, width: 100, height: 100 });
});

void test("reports invalid record lengths without reading outside their record", () => {
  const bytes = createEmfResource();
  new DataView(bytes.buffer).setUint32(92, 4, true);

  assert.match(addMetafilePreview(bytes)?.issues?.join(" ") ?? "", /invalid size/);
  assert.ok(addMetafilePreview(createPlaceableWmfResource().subarray(0, 21))?.issues?.length);
  assert.equal(addMetafilePreview(new Uint8Array(20)), null);
});

void test("preserves unsupported records and explicitly marks the drawing as partial", () => {
  const result = addMetafilePreview(createEmfResource([createEmfRecord(999, new Uint8Array())]));

  assert.match(result?.issues?.join(" ") ?? "", /partial.*999/);
  assert.equal(result?.preview?.vector?.records?.[1]?.type, 999);
});
