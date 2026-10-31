import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { readEmbeddedResourceContent, previewEmbeddedResources }
  from "../../../../analyzers/embedded-resources/content.js";
import { decodeRcc } from "../../../../analyzers/embedded-resources/rcc.js";
import { decodeGResource } from "../../../../analyzers/embedded-resources/gresource.js";
import { resolveResourcePayload } from "../../../../analyzers/embedded-resources/payload.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { embeddedResourceFixture, minimalRcc } from "../../../fixtures/embedded-resource-builders.js";

for (const name of ["oracle-v1.rcc", "oracle-v3.rcc", "oracle.gresource"]) {
  void test(`extracts and previews source-built ${name} contents locally`, async () => {
    const file = new MockFile(embeddedResourceFixture(name));
    const decoded = await (name.endsWith("rcc") ? decodeRcc : decodeGResource)(file, 0, file.size);
    assert.ok(decoded.value);
    const entry = decoded.value.entries.find(item => item.name === "message.txt");
    assert.ok(entry?.payload);
    const payload = resolveResourcePayload(decoded.value.format, entry);
    assert.ok(payload);
    const content = await readEmbeddedResourceContent(file, payload, 2000);
    assert.deepEqual(content.issues, []);
    assert.equal(new TextDecoder().decode(content.value!), "Binary101 resource oracle ".repeat(50));
    const budget = { remainingBytes: 2000 };
    assert.deepEqual(await previewEmbeddedResources(file, decoded.value, budget), []);
    assert.equal(entry.preview?.textPreview, "Binary101 resource oracle ".repeat(50));
    assert.equal(budget.remainingBytes, 672);
  });
}

void test("bounds content allocation, validates sizes and reports decompression failures", async () => {
  const file = new MockFile(new Uint8Array([0, 1]));
  const payload = { offset: 0, size: 2, compression: "none" as const, uncompressedSize: 2 };
  assert.deepEqual((await readEmbeddedResourceContent(file, payload, 2)).value, file.data);
  assert.deepEqual((await readEmbeddedResourceContent(file, { ...payload, size: 0, uncompressedSize: 0 }, 0)).value,
    new Uint8Array());
  assert.match((await readEmbeddedResourceContent(file, payload, 1)).issues.join(), /budget/);
  assert.match((await readEmbeddedResourceContent(file, { ...payload, uncompressedSize: 1 }, 1)).issues.join(), /budget/);
  assert.match((await readEmbeddedResourceContent(file, { ...payload, uncompressedSize: -1 }, 2)).issues.join(), /budget/);
  assert.match((await readEmbeddedResourceContent(file, { ...payload, uncompressedSize: 0.5 }, 2)).issues.join(), /budget/);
  assert.match((await readEmbeddedResourceContent(file, { ...payload, uncompressedSize: 1 }, 2)).issues.join(), /mismatch/);
  assert.equal((await readEmbeddedResourceContent(file, { ...payload, compression: "zlib" }, 2)).value, null);
  assert.equal((await readEmbeddedResourceContent(file, { ...payload, compression: "zstd" }, 2)).value, null);
  const compressed = new MockFile(deflateSync(new TextEncoder().encode("hello")));
  const zipped = { offset: 0, size: compressed.size, compression: "zlib" as const, uncompressedSize: 4 };
  assert.match((await readEmbeddedResourceContent(compressed, zipped, 100)).issues.join(), /exceeds/);
  assert.match((await readEmbeddedResourceContent(compressed, { ...zipped, uncompressedSize: 6 }, 100)).issues.join(),
    /mismatch/);
});

void test("assembles multiple zlib output chunks and releases stream locks on success and error", async context => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = DecompressionStream;
  const streams: ReadableStream[] = [];
  globals["DecompressionStream"] = class {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<BufferSource>;
    constructor(format: CompressionFormat) {
      const decompressor = new original(format);
      this.readable = decompressor.readable;
      this.writable = decompressor.writable;
      streams.push(this.readable);
    }
  };
  context.after(() => { globals["DecompressionStream"] = original; });
  const expected = Uint8Array.from({ length: 128 * 1024 }, (_, index) => index % 251);
  const file = new MockFile(deflateSync(expected));
  const payload = { offset: 0, size: file.size, uncompressedSize: expected.length, compression: "zlib" as const };
  const result = await readEmbeddedResourceContent(file, payload, expected.length);
  assert.equal(Buffer.from(result.value ?? []).equals(Buffer.from(expected)), true);
  assert.equal(streams[0]?.locked, false);
  const failure = await readEmbeddedResourceContent(file, { ...payload, uncompressedSize: 0 }, expected.length);
  assert.equal(failure.value, null);
  assert.equal(streams[1]?.locked, false);
});

void test("caches shared previews and reports skipped or corrupt content without losing metadata", async () => {
  const fixture = minimalRcc();
  const file = new MockFile(fixture.bytes);
  const decoded = await decodeRcc(file, 0, file.size);
  assert.ok(decoded.value);
  decoded.value.entries.push({ ...decoded.value.entries[1]! });
  const budget = { remainingBytes: 5 };
  assert.deepEqual(await previewEmbeddedResources(file, decoded.value, budget), []);
  assert.equal(budget.remainingBytes, 0);
  assert.deepEqual(decoded.value.entries[2]?.preview, decoded.value.entries[1]?.preview);
  const issues = await previewEmbeddedResources(file, decoded.value, { remainingBytes: 0 });
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /Content at .*budget/);
});

void test("handles non-previewable binary and empty contents", async () => {
  const fixture = minimalRcc(1, new Uint8Array([0, 1, 2]));
  const file = new MockFile(fixture.bytes);
  const decoded = await decodeRcc(file, 0, file.size);
  assert.ok(decoded.value);
  assert.deepEqual(await previewEmbeddedResources(file, decoded.value, { remainingBytes: 3 }), []);
  assert.equal(decoded.value.entries[1]?.preview, undefined);
});

void test("retains preview diagnostics from existing XML preview decoders", async () => {
  const fixture = minimalRcc(1, new TextEncoder().encode("<root>"));
  const file = new MockFile(fixture.bytes);
  const decoded = await decodeRcc(file, 0, file.size);
  assert.ok(decoded.value);
  assert.deepEqual(await previewEmbeddedResources(file, decoded.value, { remainingBytes: 100 }), []);
  assert.ok(decoded.value.entries[1]?.preview?.previewIssues?.length);
});
