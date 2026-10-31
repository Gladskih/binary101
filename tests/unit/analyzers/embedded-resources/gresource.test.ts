import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeGResource } from "../../../../analyzers/embedded-resources/gresource.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { embeddedResourceFixture, minimalGResource, overwriteResource, gResourceBeforeTable }
  from "../../../fixtures/embedded-resource-builders.js";

void test("decodes generated GLib GResource metadata, directories and compressed values", async () => {
  const bytes = embeddedResourceFixture("oracle.gresource");
  const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.ok(result.value);
  assert.equal(result.value.version, 0);
  assert.equal(result.value.options, 0);
  assert.equal(result.value.byteSwapped, false);
  assert.equal(result.value.bloomShift, 5);
  assert.deepEqual(result.value.bloomWords, []);
  assert.deepEqual(result.value.buckets, [0, 4, 4, 5, 5]);
  assert.deepEqual(result.value.entries.map(item => [item.name, item.parent, item.type]), [
    ["org/", 2, "L"], ["message.txt", 4, "v"], ["/", null, "L"],
    ["plain.txt", 4, "v"], ["binary101/", 0, "L"]
  ]);
  assert.deepEqual(result.value.entries[4]?.children, [1, 3]);
  assert.equal(result.value.entries[1]?.payload?.uncompressedSize, 1300);
  assert.equal(result.value.entries[3]?.payload?.size, 28);
});

void test("resolves a prefixed GResource whose data precedes the root table", async () => {
  const original = gResourceBeforeTable();
  const bytes = new Uint8Array(original.length + 9);
  bytes.set(original, 9);
  const result = await decodeGResource(new MockFile(bytes), 9, original.length);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.value?.root, { offset: 137, size: 64 });
  assert.deepEqual(result.value?.entries[1]?.payload,
    { offset: 49, size: 6 });
  assert.equal(result.value?.entries[1]?.keyOffset, 34);
  assert.deepEqual(result.value?.entries[1]?.value, { offset: 41, size: 22 });
});

void test("rejects descending hash bucket offsets before attempting resource lookup", async () => {
  const bytes = overwriteResource(embeddedResourceFixture("oracle.gresource"), 40, 3);
  const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, ["GVDB buckets are not ordered or exceed item count"]);
});

void test("bounds the complete GVariant signature and accepts structurally empty compressed arrays", async () => {
  const bytes = minimalGResource();
  const view = new DataView(bytes.buffer);
  view.setUint32(84, 110, true);
  assert.deepEqual((await decodeGResource(new MockFile(bytes), 0, bytes.length)).issues,
    ["Truncated GResource GVariant"]);
  view.setUint32(84, 111, true);
  view.setUint32(96, 0, true);
  view.setUint32(100, 1, true);
  bytes.set(new TextEncoder().encode("\0(uuay)"), 104);
  const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.value?.entries[1]?.payload,
    { offset: 104, size: 0, uncompressedSize: 0 });
});

void test("keeps GResource tuple integers little endian regardless of the GVDB signature", async () => {
  const bytes = minimalGResource();
  bytes.set(new TextEncoder().encode("raVGtnai"));
  const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.equal(result.value?.byteSwapped, true);
  assert.equal(result.value?.entries[1]?.payload?.size, 6);
});

void test("preserves little-endian compressed tuples with a swapped GVDB signature", async () => {
  // Confirmed with GLib's gresource details/extract: get_raw_value ignores byteSwapped.
  const bytes = embeddedResourceFixture("oracle.gresource");
  bytes.set(new TextEncoder().encode("raVGtnai"));
  const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.equal(result.value?.byteSwapped, true);
  assert.equal(result.value?.entries[1]?.payload?.uncompressedSize, 1300);
  assert.equal(result.value?.entries[3]?.payload?.size, 28);
});

for (const [label, offset, value, encoding] of [
  ["signature", 0, 0, "le32"], ["version", 8, 1, "le32"], ["options", 12, 1, "le32"],
  ["root alignment", 16, 25, "le32"], ["root header overlap", 16, 20, "le32"],
  ["root size", 20, 23, "le32"], ["truncated table", 20, 136, "le32"],
  ["bloom count", 24, 0x07ffffff, "le32"], ["bucket count", 28, 0, "le32"],
  ["bucket overflow", 28, 0xffffffff, "le32"], ["bloom exclusion", 32, 0, "le32"],
  ["bucket first item", 36, 1, "le32"], ["bucket out of range", 36, 3, "le32"],
  ["hash", 40, 0, "le32"], ["parent cycle", 44, 1, "le32"],
  ["key bounds", 48, 132, "le32"], ["key header overlap", 48, 0, "le32"],
  ["key table overlap", 48, 24, "le32"], ["empty key", 52, 0, "le16"],
  ["unknown type", 54, 72, "u8"], ["reserved byte", 55, 1, "u8"],
  ["value pointer alignment", 56, 93, "le32"], ["value header overlap", 56, 0, "le32"],
  ["value table overlap", 56, 24, "le32"], ["reversed value pointer", 60, 0, "le32"],
  ["child list length", 60, 95, "le32"], ["root path", 88, 0, "u8"],
  ["invalid UTF-8", 89, 0xff, "u8"], ["child cycle", 92, 0, "le32"],
  ["child out of range", 92, 2, "le32"], ["parent mismatch", 68, 1, "le32"],
  ["variant signature", 113, 120, "u8"], ["unknown flags", 100, 2, "le32"],
  ["declared size", 96, 8, "le32"], ["NUL terminator", 110, 1, "u8"]
] as const) {
  void test(`rejects GResource ${label}`, async () => {
    const bytes = overwriteResource(minimalGResource(), offset, value, encoding);
    const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
    assert.equal(result.value, null);
    assert.equal(result.issues.length, 1);
    assert.equal(typeof result.issues[0], "string");
    assert.notEqual(result.issues[0], "");
    assert.match(result.issues[0]!, {
      signature: /Invalid GVDB signature/, version: /Unsupported GVDB version or options/,
      options: /Unsupported GVDB version or options/, "root alignment": /Invalid GVDB root pointer/,
      "root header overlap": /Invalid GVDB root pointer/, "root size": /Invalid GVDB root pointer/,
      "truncated table": /Resource structure is truncated or out of bounds/,
      "bloom count": /Invalid GVDB hash table dimensions/, "bucket count": /Invalid GVDB hash table dimensions/,
      "bucket overflow": /Invalid GVDB hash table dimensions/, "bloom exclusion": /GVDB bloom filter excludes/,
      "bucket first item": /GVDB buckets are not ordered/, "bucket out of range": /GVDB buckets are not ordered/,
      hash: /GVDB key hash mismatch/, "parent cycle": /no unique \/ root/,
      "key bounds": /Invalid GVDB key pointer/, "key header overlap": /Invalid GVDB key pointer/,
      "key table overlap": /overlaps the hash table/, "empty key": /Invalid GVDB key/,
      "unknown type": /not a GResource directory or value/, "reserved byte": /Nonzero GVDB reserved byte/,
      "value pointer alignment": /Invalid GVDB value pointer/, "value header overlap": /Invalid GVDB value pointer/,
      "value table overlap": /overlaps the hash table/, "reversed value pointer": /Invalid GVDB value pointer/,
      "child list length": /not a uint32 array/, "root path": /Invalid GVDB key/,
      "invalid UTF-8": /encoded data/, "child cycle": /invalid, shared or cyclic/,
      "child out of range": /invalid, shared or cyclic/, "parent mismatch": /parent and child list disagree/,
      "variant signature": /not a GResource \(uuay\)/, "unknown flags": /Unsupported GResource flags/,
      "declared size": /size and byte array disagree/, "NUL terminator": /missing its NUL terminator/
    }[label]);
  });
}

const truncatedGResource = embeddedResourceFixture("oracle.gresource");
for (let size = 0; size < truncatedGResource.length; size += 1) {
  void test(`rejects truncated GResource prefix ${size} without throwing`, async () => {
    const result = await decodeGResource(new MockFile(truncatedGResource.subarray(0, size)), 0, size);
    assert.equal(result.value, null, `prefix ${size}`);
  });
}

void test("hashes non-ASCII GResource keys using signed UTF-8 bytes", async () => {
  const bytes = minimalGResource();
  const view = new DataView(bytes.buffer);
  view.setUint16(76, 2, true);
  view.setUint32(64, 193426080, true); // GNOME djb_hash("/é"), signed bytes 0xc3, 0xa9.
  bytes.set(new TextEncoder().encode("é"), 89);
  const result = await decodeGResource(new MockFile(bytes), 0, bytes.length);
  assert.deepEqual(result.issues, []);
  assert.equal(result.value?.entries[1]?.name, "é");
});

void test("rejects a GVDB signature without a validated resource table", async () => {
  const result = await decodeGResource(new MockFile(new TextEncoder().encode("GVariant")), 0, 8);
  assert.equal(result.value, null);
  assert.match(result.issues.join(" "), /truncated/);
});
