"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeLiteralString,
  extractDictionary,
  parseCatalogDictionary,
  parseInfoDictionary,
  parsePagesDictionary,
  parseTrailerDictionary,
  parseIndirectRef
} from "../../analyzers/pdf/dictionary.js";

const sampleDict = "<< /Size 5 /Root 1 0 R /Info 2 0 R /ID [<aa><bb>] >>";

void test("extractDictionary finds balanced brackets", () => {
  const text = "padding " + sampleDict + " tail";
  assert.strictEqual(extractDictionary(text, 0)?.trim(), sampleDict);
});

void test("parseTrailerDictionary extracts size, root, info and id", () => {
  const trailer = parseTrailerDictionary(sampleDict);
  assert.strictEqual(trailer.size, 5);
  assert.deepEqual(trailer.rootRef, { objectNumber: 1, generation: 0 });
  assert.deepEqual(trailer.infoRef, { objectNumber: 2, generation: 0 });
  assert.deepEqual(trailer.id, ["aa", "bb"]);
});

void test("parseInfoDictionary decodes literal strings", () => {
  const dict = "<< /Title (Hello\\nWorld) /Producer (PDFGen) >>";
  const parsed = parseInfoDictionary(dict);
  assert.strictEqual(parsed?.title, "Hello\nWorld");
  assert.strictEqual(parsed?.producer, "PDFGen");
});

void test("parseCatalogDictionary captures references", () => {
  const dict = "<< /Pages 10 0 R /Names 8 0 R /Outlines 9 0 R >>";
  const catalog = parseCatalogDictionary(dict);
  assert.deepEqual(catalog?.pagesRef, { objectNumber: 10, generation: 0 });
  assert.deepEqual(catalog?.namesRef, { objectNumber: 8, generation: 0 });
  assert.deepEqual(catalog?.outlinesRef, { objectNumber: 9, generation: 0 });
});

void test("parsePagesDictionary extracts count", () => {
  const parsed = parsePagesDictionary("<< /Count 12 >>");
  assert.strictEqual(parsed?.count, 12);
});

void test("parseIndirectRef returns null on missing tokens", () => {
  assert.strictEqual(parseIndirectRef("<< /Root notref >>", "Root"), null);
});

void test("decodeLiteralString handles escaped characters", () => {
  assert.strictEqual(decodeLiteralString("\\(abc\\)\\n\\r\\t\\\\s"), "(abc)\n\r\t\\s");
});
