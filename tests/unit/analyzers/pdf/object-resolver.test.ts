import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createObjectResolver } from "../../../../analyzers/pdf/object-resolver.js";
import type { PdfXrefEntry } from "../../../../analyzers/pdf/types.js";

const root = { objectNumber: 4, generation: 0 };
const child = { objectNumber: 7, generation: 0 };
const rootText = "<< /Type /Catalog >>";
const childText = "<< /Type /Pages >>";

const compressedResolver = (first: string, second: string, streamGeneration = 0) => {
  const index = "4 0 7 " + first.length + "\n";
  const body = index + first + second;
  const header = "12 " + streamGeneration + " obj\n<< /Type /ObjStm /N 2 /First " + index.length +
    " /Length " + body.length + " >>\nstream\n";
  const file = new File([header, body, "\nendstream\nendobj"], "compressed.pdf");
  const reader = createFileRangeReader(file, 0, file.size);
  let reads = 0;
  const watched = { ...reader, readBytes: (offset: number, length: number) => {
    if (offset === header.length && length === body.length) reads += 1;
    return reader.readBytes(offset, length);
  } };
  const entries = new Map<number, PdfXrefEntry>([
    [4, { kind: "compressed", objectNumber: 4, streamObject: 12, index: 0 }],
    [7, { kind: "compressed", objectNumber: 7, streamObject: 12, index: 1 }],
    [12, { kind: "direct", objectNumber: 12, offset: 0, generation: streamGeneration }]
  ]);
  const issues: string[] = [];
  return { resolve: createObjectResolver(watched, entries, null, issues), issues, payloadReads: () => reads };
};

void test("only reads a shared object stream once for independent object references", async () => {
  const subject = compressedResolver(rootText, childText);
  assert.equal((await subject.resolve.dictionary(root, "Catalog"))?.raw, rootText);
  assert.equal((await subject.resolve.dictionary(child, "Pages"))?.raw, childText);
  assert.equal(subject.payloadReads(), 1);
  assert.deepEqual(subject.issues, []);
});

void test("a compressed object must point to a generation-zero object stream", async () => {
  const subject = compressedResolver(rootText, childText, 1);
  assert.equal(await subject.resolve.dictionary(root, "Catalog"), null);
  assert.deepEqual(subject.issues, ["Catalog 4 0 R: missing generation-zero object stream."]);
  assert.equal(subject.payloadReads(), 0);
});

for (const text of ["2", rootText + " 39"]) {
  void test("compressed dictionary must occupy the referenced object slot", async () => {
    const subject = compressedResolver(text, childText);
    assert.equal(await subject.resolve.dictionary(root, "Test"), null);
    assert.deepEqual(subject.issues, ["Test 4 0 R: invalid compressed dictionary."]);
  });
}

void test("compressed object size budget applies to the referenced slot length", async () => {
  const raw = "<< /Custom (" + "x".repeat(65_520) + ") >>";
  const full = compressedResolver(rootText, raw);
  const large = compressedResolver(rootText, raw + " ");
  assert.equal(raw.length, 65_536);
  assert.equal((await full.resolve.dictionary(child, "Test"))?.raw.length, 65_536);
  assert.equal(await large.resolve.dictionary(child, "Test"), null);
  assert.deepEqual(large.issues, ["Test 7 0 R: compressed dictionary exceeds the byte limit."]);
});

void test("a stream dictionary cannot come from a compressed object slot", async () => {
  const subject = compressedResolver(rootText, childText);
  assert.equal(await subject.resolve.streamDictionary(child, "Test"), null);
  assert.deepEqual(subject.issues, ["Test 7 0 R: stream must be a direct xref entry."]);
});
