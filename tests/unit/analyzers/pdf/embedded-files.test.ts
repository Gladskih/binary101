import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePdf } from "../../../../analyzers/pdf/index.js";
import { createPdfObjects, createPdfWithEmbeddedFile } from "../../../fixtures/pdf-document-structure.js";

void test("resolves embedded stream metadata and combines references from both indexes", async () => {
  const pdf = await parsePdf(createPdfWithEmbeddedFile());
  assert.deepEqual(pdf.embeddedFiles, [{
    fileSpec: { objectNumber: 8, generation: 0 }, stream: { objectNumber: 11, generation: 0 },
    name: "notes.txt", description: "Read &lt;notes&gt;", mediaType: "text/plain",
    decodedSize: 4, storedSize: 4, relationship: "Data",
    sources: ["EmbeddedFiles name tree", "Catalog /AF"]
  }]);
});

const associatedFile = (entry: string, stream: string, trailer = "", name = "(example)") =>
  createPdfObjects([
    "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [" + name + " " + entry + "] >> >> >>",
    "<< /Type /Pages /Count 0 /Kids [] >>", stream
  ], trailer);

void test("reads a direct file specification and an embedded stream with omitted optional Type", async () => {
  const pdf = await parsePdf(associatedFile("<< /EF << /F 3 0 R >> >>",
    "<< /Length 0 >>\nstream\n\nendstream"));
  assert.deepEqual(pdf.embeddedFiles, [{
    fileSpec: null, stream: { objectNumber: 3, generation: 0 }, name: "example", description: null,
    mediaType: null, decodedSize: null, storedSize: 0, relationship: null, sources: ["EmbeddedFiles name tree"]
  }]);
  assert.deepEqual(pdf.issues, []);
});

void test("retains structural metadata for encrypted documents with encrypted names", async () => {
  const pdf = await parsePdf(associatedFile("<< /F (ciphertext) /EF << /F 3 0 R >> >>",
    "<< /Length 0 >>\nstream\n\nendstream", "/Encrypt << /Filter /Standard >>"));
  assert.equal(pdf.embeddedFiles[0]?.name, null);
  assert.equal(pdf.embeddedFiles[0]?.storedSize, 0);
  assert.match(pdf.issues.join("\n"), /Encrypted strings/);
});

for (const [stream, warning] of [
  ["<< /Type /EmbeddedFile >>", "Embedded file stream 3 0 R: expected a stream."],
  ["<< /Type /Other /Length 0 >>\nstream\n\nendstream", "Embedded file stream 3 has an unexpected /Type."]
] as const) {
  void test("rejects a referenced object that is not an embedded file stream", async () => {
    const pdf = await parsePdf(associatedFile("<< /EF << /F 3 0 R >> >>", stream));
    assert.deepEqual(pdf.embeddedFiles, []);
    assert.deepEqual(pdf.issues, [warning]);
  });
}

void test("stops a cyclic name tree and flags malformed associated-file entries", async () => {
  const pdf = await parsePdf(createPdfObjects([
    "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 3 0 R >> /AF /Invalid >>",
    "<< /Type /Pages /Count 0 /Kids [] >>", "<< /Kids [3 0 R] >>"
  ]));
  assert.deepEqual(pdf.embeddedFiles, []);
  assert.deepEqual(pdf.issues, ["Repeated or cyclic EmbeddedFiles node 3.",
    "Catalog /AF is not an array of file specifications."]);
});

for (const [index, warning] of [
  ["/EmbeddedFiles /Invalid", "EmbeddedFiles node is not a dictionary or indirect reference."],
  ["/EmbeddedFiles << /Kids /Invalid >>", "EmbeddedFiles node lacks a valid /Names or /Kids array."],
  ["/EmbeddedFiles << /Kids [null] >>", "EmbeddedFiles /Kids contains an invalid indirect reference."],
  ["/EmbeddedFiles << /Names [(orphan key)] >>",
    "EmbeddedFiles /Names is not an array of name and file specification pairs."]
] as const) {
  void test("reports malformed EmbeddedFiles indexes", async () => {
    const pdf = await parsePdf(createPdfObjects([
      "<< /Type /Catalog /Pages 2 0 R /Names << " + index + " >> >>",
      "<< /Type /Pages /Count 0 /Kids [] >>"
    ]));
    assert.deepEqual(pdf.embeddedFiles, []);
    assert.deepEqual(pdf.issues, [warning]);
  });
}

void test("embedded files require EF to identify an actual stream", async () => {
  const pdf = await parsePdf(associatedFile("<< /EF << /UF (reference required) >> >>",
    "<< /Length 0 >>\nstream\n\nendstream"));
  assert.deepEqual(pdf.embeddedFiles, []);
  assert.deepEqual(pdf.issues, ["File specification /EF lacks a supported /UF or /F stream reference."]);
});

void test("embedded file inspection reports a truncated list after its reference budget", async () => {
  const pdf = await parsePdf(createPdfObjects([
    "<< /Type /Catalog /Pages 2 0 R /AF [" + "3 0 R ".repeat(513) + "] >>",
    "<< /Type /Pages /Count 0 /Kids [] >>", "<< /F (external.txt) >>"
  ]));
  assert.deepEqual(pdf.embeddedFiles, []);
  assert.deepEqual(pdf.issues, ["Embedded file inspection limit reached."]);
});

void test("embedded file index coalesces references with different PDF whitespace", async () => {
  const pdf = await parsePdf(createPdfObjects([
    "<< /Type /Catalog /Pages 2 0 R /AF [3 0 R 3% comment\n0 R] >>",
    "<< /Type /Pages /Count 0 /Kids [] >>", "<< /F (sample) /EF << /F 4 0 R >> >>",
    "<< /Length 0 >>\nstream\n\nendstream"
  ]));
  assert.equal(pdf.embeddedFiles.length, 1);
  assert.deepEqual(pdf.embeddedFiles[0]?.sources, ["Catalog /AF"]);
  assert.deepEqual(pdf.issues, []);
});
