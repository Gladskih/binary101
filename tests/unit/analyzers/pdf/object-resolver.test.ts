import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
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

const directResolver = (text: string, offset = 0) => {
  const file = new File([text], "direct.pdf");
  const index = new Map<number, PdfXrefEntry>([
    [4, { kind: "direct", objectNumber: 4, generation: 0, offset }]
  ]);
  const issues: string[] = [];
  return { resolve: createObjectResolver(createFileRangeReader(file, 0, file.size), index, null, issues), issues };
};

void test("requires endobj at the dictionary boundary and accepts it at EOF", async () => {
  const valid = directResolver("4 0 obj " + rootText + " endobj");
  const invalid = directResolver("4 0 obj " + rootText + " x endobj");
  assert.equal((await valid.resolve.dictionary(root, "Catalog"))?.raw, rootText);
  assert.equal(await invalid.resolve.dictionary(root, "Catalog"), null);
  assert.deepEqual(invalid.issues, ["Catalog 4 0 R: dictionary does not terminate with endobj."]);
});

void test("rejects a direct object offset equal to the input length", async () => {
  const subject = directResolver("text", 4);
  assert.equal(await subject.resolve.dictionary(root, "Catalog"), null);
  assert.deepEqual(subject.issues, ["Catalog 4 0 R: offset is outside the file."]);
});

void test("requires a stream marker immediately after dictionary trivia", async () => {
  const subject = directResolver("4 0 obj " + rootText + " x stream\n");
  assert.equal(await subject.resolve.streamDictionary(root, "Stream"), null);
  assert.deepEqual(subject.issues, ["Stream 4 0 R: expected a stream."]);
});

const budgetedResolver = (sizes: number[]) => {
  const parts: BlobPart[] = [];
  const entries = new Map<number, PdfXrefEntry>();
  const payloads = new Set<number>();
  let offset = 0;
  sizes.forEach((size, index) => {
    const objectNumber = index + 1;
    const streamNumber = objectNumber + 10;
    const directory = objectNumber + " 0 99 " + rootText.length + "\n";
    const decoded = Buffer.alloc(size, 32);
    decoded.write(directory + rootText, "ascii");
    const data = deflateSync(decoded);
    const header = streamNumber + " 0 obj\n<< /Type /ObjStm /N 2 /First " + directory.length +
      " /Length " + data.length + " /Filter /FlateDecode >>\nstream\n";
    const suffix = "\nendstream\nendobj\n";
    parts.push(header, data, suffix);
    payloads.add(offset + header.length);
    entries.set(objectNumber, { kind: "compressed", objectNumber, streamObject: streamNumber, index: 0 });
    entries.set(streamNumber, { kind: "direct", objectNumber: streamNumber, generation: 0, offset });
    offset += header.length + data.length + suffix.length;
  });
  const file = new File(parts, "decoded-budget.pdf");
  const issues: string[] = [];
  const reader = createFileRangeReader(file, 0, file.size);
  let payloadReads = 0;
  const watched = { ...reader, readBytes: (offset: number, length: number) => {
    if (payloads.has(offset)) payloadReads += 1;
    return reader.readBytes(offset, length);
  } };
  return { resolve: createObjectResolver(watched, entries, null, issues), issues,
    payloadReads: () => payloadReads };
};

void test("charges decoded bytes cumulatively and accepts the exact aggregate budget", async () => {
  // Four structural streams of 8 MiB fill the per-document 32 MiB cache.
  const size = 8 * 1024 * 1024;
  const subject = budgetedResolver([size, size, size, size, 128]);
  for (const objectNumber of [1, 2, 3, 4]) {
    assert.equal((await subject.resolve.dictionary({ objectNumber, generation: 0 }, "Test"))?.raw, rootText);
  }
  assert.equal(await subject.resolve.dictionary({ objectNumber: 5, generation: 0 }, "Test"), null);
  assert.equal(subject.payloadReads(), 4);
  assert.deepEqual(subject.issues, ["Test 5 0 R: decoded object stream budget reached."]);
});

void test("a decoded stream that crosses the aggregate budget is rejected", async () => {
  const size = 8 * 1024 * 1024;
  const subject = budgetedResolver([size, size, size, size - 1, 128]);
  for (const objectNumber of [1, 2, 3, 4]) {
    assert.equal((await subject.resolve.dictionary({ objectNumber, generation: 0 }, "Test"))?.raw, rootText);
  }
  assert.equal(await subject.resolve.dictionary({ objectNumber: 5, generation: 0 }, "Test"), null);
  assert.equal(subject.payloadReads(), 5);
  assert.deepEqual(subject.issues, ["Test 5 0 R: decoded object stream budget reached."]);
});
