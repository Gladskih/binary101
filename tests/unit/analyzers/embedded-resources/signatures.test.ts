import assert from "node:assert/strict";
import { test } from "node:test";
import { findResourceSignatures } from "../../../../analyzers/embedded-resources/signatures.js";
import type { ResourceSignature } from "../../../../analyzers/embedded-resources/signatures.js";
import { MockFile } from "../../../helpers/mock-file.js";

const collect = async (file: File, sections = [{ name: ".data", offset: 0, size: file.size }]) => {
  const found: ResourceSignature[] = [];
  for await (const signature of findResourceSignatures(file, sections)) found.push(signature);
  return found;
};

void test("finds signatures at unaligned offsets and final bytes without matching partial literals", async () => {
  const file = new MockFile(new TextEncoder().encode("?qres!GVariant?raVGtnai.qre"));
  assert.deepEqual(await collect(file), [
    { offset: 1, end: file.size, kind: "rcc" }, { offset: 6, end: file.size, kind: "gresource" },
    { offset: 15, end: file.size, kind: "gresource" }
  ]);
  assert.deepEqual(await collect(new MockFile(new TextEncoder().encode("qres"))),
    [{ offset: 0, end: 4, kind: "rcc" }]);
  assert.deepEqual(await collect(new MockFile(new TextEncoder().encode("GVarian"))), []);
  assert.deepEqual(await collect(new MockFile(new TextEncoder().encode("ares QVariant aaVGtnai"))), []);
});

void test("skips zero-byte sections, merges ranges away from zero and releases stream locks", async () => {
  let reads = 0;
  const empty = { size: 1, slice: () => { reads += 1; return new Blob(); } } as File;
  assert.deepEqual(await collect(empty, [{ name: "zero", offset: 0, size: 0 }]), []);
  assert.equal(reads, 0);
  const data = new TextEncoder().encode("...qresGVariant");
  const streams: ReadableStream<Uint8Array>[] = [];
  const file = { size: data.length, slice: (offset: number, end: number) => ({ stream: () => {
    const stream = new Blob([data.slice(offset, end)]).stream();
    streams.push(stream);
    return stream;
  } }) } as File;
  assert.deepEqual(await collect(file, [{ name: "a", offset: 3, size: 8 },
    { name: "b", offset: 7, size: 8 }]), [
    { offset: 3, end: 15, kind: "rcc" }, { offset: 7, end: 15, kind: "gresource" }
  ]);
  assert.equal(streams.length, 1);
  assert.equal(streams[0]?.locked, false);
});

const chunkedFile = (chunkSize: number): File => {
  const data = new TextEncoder().encode("qresGVariantraVGtnaiqres");
  return { size: data.length, slice: () => ({ stream: () => new ReadableStream<Uint8Array>({
    start(controller) {
      for (let index = 0; index < data.length; index += chunkSize) {
        controller.enqueue(data.slice(index, index + chunkSize));
      }
      controller.close();
    }
  }) }) } as File;
};

// Include chunks shorter and longer than the eight-byte GVDB signature.
for (let chunkSize = 1; chunkSize <= 12; chunkSize += 1) {
  void test(`streams signatures across ${chunkSize}-byte chunk boundaries`, async () => {
    assert.deepEqual((await collect(chunkedFile(chunkSize))).map(value => value.offset), [0, 4, 12, 20]);
  });
}

void test("merges aliases, preserves disjoint section ends, skips invalid ranges and empty streams", async () => {
  const file = new MockFile(new TextEncoder().encode("qresGVariant"));
  assert.deepEqual(await collect(file, [
    { name: "invalid", offset: -1, size: 5 }, { name: "b", offset: 2, size: 10 },
    { name: "a", offset: 0, size: 6 }, { name: "alias", offset: 1, size: 3 },
    { name: "beyond", offset: 10, size: 4 }, { name: "empty", offset: 0, size: 0 }
  ]), [{ offset: 0, end: 12, kind: "rcc" }, { offset: 4, end: 12, kind: "gresource" }]);
  assert.deepEqual(await collect(file, [{ name: "a", offset: 0, size: 4 },
    { name: "b", offset: 4, size: 8 }]), [
    { offset: 0, end: 4, kind: "rcc" }, { offset: 4, end: 12, kind: "gresource" }
  ]);
  assert.deepEqual(await collect(new MockFile(new Uint8Array())), []);
  assert.deepEqual(await collect(file, [{ name: "whole", offset: 0, size: 12 },
    { name: "nested", offset: 1, size: 3 }]), [
    { offset: 0, end: 12, kind: "rcc" }, { offset: 4, end: 12, kind: "gresource" }
  ]);
});
