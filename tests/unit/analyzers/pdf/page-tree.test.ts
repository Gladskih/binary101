import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePdf } from "../../../../analyzers/pdf/index.js";
import { createPdfObjects, createPdfWithEmbeddedFile } from "../../../fixtures/pdf-document-structure.js";

void test("page tree uses depth-first Kids order and propagates page attributes", async () => {
  const result = await parsePdf(createPdfWithEmbeddedFile());
  assert.equal(result.pages?.count, 2);
  assert.deepEqual(result.pages?.entries, [
    { ref: { objectNumber: 3, generation: 0 }, mediaBox: [0, 0, 612, 792],
      cropBox: null, rotation: 90, userUnit: 1 },
    { ref: { objectNumber: 5, generation: 0 }, mediaBox: [321, 456, -0.5, -2],
      cropBox: [10, 20, 200, 400], rotation: 0, userUnit: 2 }
  ]);
  assert.deepEqual(result.issues, []);
});

const focusedTree = (kids: string, page: string, count = 1): File => createPdfObjects([
  "<< /Type /Catalog /Pages 2 0 R >>",
  "<< /Type /Pages /Count " + count + " /Kids " + kids + " /MediaBox [0 0 200 300] >>",
  page
]);

const leaf = "<< /Type /Page /Parent 2 0 R >>";

void test("page tree compares declared and traversed counts only after a complete walk", async () => {
  const complete = await parsePdf(focusedTree("[3 0 R]", leaf, 2));
  const incomplete = await parsePdf(focusedTree("[3 0 R 2 0 R]", leaf, 2));
  assert.deepEqual(complete.issues, ["Page tree root /Count declares 2 pages but traversal found 1."]);
  assert.deepEqual(incomplete.issues, ["Repeated or cyclic page-tree object 2."]);
  assert.equal(incomplete.pages?.entries.length, 1);
});

for (const [kids, page, warning] of [
  ["/Unknown", leaf, "Page-tree node 2 lacks a valid /Kids array."],
  ["[null]", leaf, "Page-tree /Kids contains an invalid indirect reference."],
  ["[4 0 R]", leaf, "Page tree 4 0 R: cross-reference entry is unavailable."],
  ["[3 0 R]", "<< /Type /Wrong /Parent 2 0 R >>", "Page-tree child 3 has an invalid /Type."],
  ["[3 0 R]", "<< /Type /Page /Parent 4 0 R >>", "Page-tree object 3 has a mismatched /Parent."]
]) {
  void test("reports broken page-tree data", async () => {
    const result = await parsePdf(focusedTree(kids!, page!));
    assert.deepEqual(result.issues, [warning]);
  });
}

void test("reports a missing MediaBox while preserving the inspected page", async () => {
  const result = await parsePdf(createPdfObjects([
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Count 1 /Kids [3 0 R] >>", leaf
  ]));
  assert.equal(result.pages?.entries[0]?.mediaBox, null);
  assert.deepEqual(result.issues, ["Page 3 has no resolved /MediaBox."]);
});

void test("page count comparison stops when the object inspection budget is exhausted", async () => {
  const leaves = Array.from({ length: 1024 }, (_, index) => String(index + 3) + " 0 R");
  const result = await parsePdf(createPdfObjects([
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Count 1024 /MediaBox [0 0 1 1] /Kids [" + leaves.join(" ") + "] >>",
    ...leaves.map(() => leaf)
  ]));
  assert.equal(result.pages?.entries.length, 1023);
  assert.deepEqual(result.issues, ["Page tree node limit reached."]);
});

const nestedPageTree = (depth: number): File => createPdfObjects([
  "<< /Type /Catalog /Pages 2 0 R >>",
  "<< /Type /Pages /Count 1 /MediaBox [0 0 1 1] /Kids [3 0 R] >>",
  ...Array.from({ length: depth - 1 }, (_, index) =>
    "<< /Type /Pages /Count 1 /Parent " + (index + 2) + " 0 R /Kids [" + (index + 4) + " 0 R] >>"),
  "<< /Type /Page /Parent " + (depth + 1) + " 0 R >>"
]);

void test("page tree refuses a descendant beyond its depth budget", async () => {
  const allowed = await parsePdf(nestedPageTree(63));
  const limited = await parsePdf(nestedPageTree(64));
  assert.equal(allowed.pages?.entries.length, 1);
  assert.deepEqual(allowed.issues, []);
  assert.deepEqual(limited.pages?.entries, []);
  assert.deepEqual(limited.issues, ["Page tree depth limit reached."]);
});
