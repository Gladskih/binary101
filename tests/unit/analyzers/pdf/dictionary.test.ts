"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeLiteralString,
  parseCatalogDictionary,
  parseInfoDictionary,
  parsePagesDictionary,
  parseTrailerDictionary
} from "../../../../analyzers/pdf/dictionary.js";
import { readDictionary } from "../../../../analyzers/pdf/syntax.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const sampleDict = "<< /Size 5 /Root 1 0 R /Info 2 0 R /ID [<aa><bb>] >>";

void test("dictionary reading is anchored after syntactic trivia", () => {
  assert.equal(readDictionary("% comment\n " + sampleDict + " tail")?.raw, sampleDict);
  assert.equal(readDictionary("junk " + sampleDict), null);
});

void test("parseTrailerDictionary extracts size, root, info and id", () => {
  const trailer = parseTrailerDictionary(expectDefined(readDictionary(sampleDict)), []);
  assert.strictEqual(trailer.size, 5);
  assert.deepEqual(trailer.rootRef, { objectNumber: 1, generation: 0 });
  assert.deepEqual(trailer.infoRef, { objectNumber: 2, generation: 0 });
  assert.deepEqual(trailer.id, ["aa", "bb"]);
});

void test("parseInfoDictionary decodes literal strings", () => {
  const dict = "<< /Title (Hello\\nWorld) /Producer (PDFGen) >>";
  const parsed = parseInfoDictionary(expectDefined(readDictionary(dict)));
  assert.strictEqual(parsed?.title, "Hello\nWorld");
  assert.strictEqual(parsed?.producer, "PDFGen");
});

void test("parseCatalogDictionary captures references", () => {
  const dict = "<< /Pages 10 0 R /Names 8 0 R /Outlines 9 0 R >>";
  const catalog = parseCatalogDictionary(expectDefined(readDictionary(dict)));
  assert.deepEqual(catalog?.pagesRef, { objectNumber: 10, generation: 0 });
  assert.deepEqual(catalog?.namesRef, { objectNumber: 8, generation: 0 });
  assert.deepEqual(catalog?.outlinesRef, { objectNumber: 9, generation: 0 });
});

void test("parsePagesDictionary extracts count", () => {
  const parsed = parsePagesDictionary(expectDefined(readDictionary("<< /Count 12 >>")));
  assert.strictEqual(parsed?.count, 12);
});

void test("metadata normalizes literal CRLF and decodes PDFDocEncoding's special bytes", () => {
  const dictionary = expectDefined(readDictionary(
    "<< /Title (a\r\nb\\\nc) /ModDate <187FAD> /Author (\\777) >>"));
  const result = parseInfoDictionary(dictionary);
  assert.equal(result.title, "a\nbc");
  assert.equal(result.modDate, "\u02d8\ufffd\ufffd");
  assert.equal(result.author, "\u00ff");
});

void test("top-level field rows retain key order and raw values", () => {
  const dictionary = expectDefined(readDictionary("<< /Root 1 0 R /Version /2.0 /Extra [null 4] >>"));
  assert.deepEqual(parseCatalogDictionary(dictionary).fields, [
    { key: "Root", value: "1 0 R" }, { key: "Version", value: "/2.0" },
    { key: "Extra", value: "[null 4]" }
  ]);
});

for (const field of ["[<a> (x)]", "[(x) <b>]", "[<a>]", "[<a> <b> <c>]"]) {
  void test("trailer does not form an ID from incomplete hex pairs", () => {
    assert.equal(parseTrailerDictionary(expectDefined(readDictionary("<< /ID " + field + " >>")), []).id, null);
  });
}

void test("trailer ignores keys in comments, strings and nested dictionaries", () => {
  const dictionary = expectDefined(readDictionary(
    "<< /Inner << /Root 4 0 R >> % /Root 8 0 R\n/Text (/Root 5 0 R >>)\n/Ro#6Ft 3 % gap\n0 R >>"));
  assert.deepEqual(parseTrailerDictionary(dictionary, []).rootRef, { objectNumber: 3, generation: 0 });
});

void test("decodeLiteralString handles escaped characters", () => {
  assert.strictEqual(decodeLiteralString("\\(abc\\)\\n\\r\\t\\\\s\\q"), "(abc)\n\r\t\\sq");
});

void test("Info decodes PDFDocEncoding, UTF-16BE and PDF 2.0 UTF-8 strings", () => {
  const dictionary = expectDefined(readDictionary(
    "<< /Title (a\\200b\\\r\nc) /Author <FE FF 04 16> /Subject <EFBBBF E282AC> " +
    "/Keywords () /Creator (a\rb) /Producer <6F2> /CreationDate (\\b\\f) >>"));
  const info = parseInfoDictionary(dictionary);
  assert.deepEqual(
    [info.title, info.author, info.subject, info.keywords, info.creator, info.producer, info.creationDate],
    ["a•bc", "Ж", "€", "", "a\nb", "o ", "\b\f"]
  );
});

void test("malformed trailer fields produce unavailable offsets and references", () => {
  const issues: string[] = [];
  const dictionary = expectDefined(readDictionary(
    "<< /Size -1 /Root null /ID [(a) (b)] /Prev 9.5 /XRefStm -9 /Encrypt null >>"));
  const trailer = parseTrailerDictionary(dictionary, issues);
  assert.deepEqual([trailer.size, trailer.rootRef, trailer.id, trailer.prev,
    trailer.xrefStreamOffset, trailer.encrypt], Array(6).fill(null));
  assert.match(issues.join("\n"), /\/Prev.*\n.*\/XRefStm/);
});

for (const input of ["<< /X (unterminated >>", "<< /X [1 >>", "<< /X <88Z> >>",
  "<< /X 1 /#58 2 >>", "<< /X " + "[".repeat(65) + "1" + "]".repeat(65) + " >>"]) {
  void test("dictionary refuses " + JSON.stringify(input), () => {
    assert.equal(readDictionary(input), null);
  });
}
