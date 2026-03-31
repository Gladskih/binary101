"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFb2File } from "../fixtures/document-sample-files.js";
import { parseFb2ForTests } from "../helpers/fb2-test-parser.js";
import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();

void test("parseFb2 skips files without FictionBook root", async () => {
  const file = new MockFile(encoder.encode("<root></root>"), "note.xml", "text/xml");
  const result = await parseFb2ForTests(file);
  assert.strictEqual(result, null);
});

void test("parseFb2 returns structured metadata for valid FB2", async () => {
  const fb2 = await parseFb2ForTests(createFb2File());
  assert.ok(fb2);
  assert.strictEqual(fb2?.title, "Example");
  assert.strictEqual(fb2?.publishInfo.publisher, "");
  assert.strictEqual(fb2?.parseError, false);
  assert.deepStrictEqual(fb2?.issues, []);
  assert.ok(fb2?.bodyCount >= 1);
});

void test("parseFb2 truncates long annotations and reads sequence", async () => {
  const longText = "Long ".repeat(100);
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<FictionBook>",
    "<description>",
    '<title-info><book-title>Annotated</book-title>',
    `<annotation><p>${longText}</p></annotation>`,
    '<sequence name="Saga" number="2"/>',
    "</title-info>",
    "</description>",
    "<body><section><p>Content</p></section></body>",
    "</FictionBook>"
  ].join("");
  const fb2 = await parseFb2ForTests(new MockFile(encoder.encode(xml), "annotated.fb2", "text/xml"));
  assert.ok(fb2);
  assert.strictEqual(fb2?.title, "Annotated");
  assert.ok(fb2?.annotation);
  assert.ok(fb2?.annotation?.endsWith("..."));
  assert.deepStrictEqual(fb2?.sequence, { name: "Saga", number: "2" });
});

void test("parseFb2 keeps malformed FB2 visible with parser issues", async () => {
  const malformed = new MockFile(
    encoder.encode("<FictionBook><description></FictionBook>"),
    "broken.fb2",
    "text/xml"
  );
  const result = await parseFb2ForTests(malformed);
  assert.ok(result);
  assert.strictEqual(result?.parseError, true);
  assert.ok(result?.issues.some(issue => issue.includes("XML parser threw")));
  assert.strictEqual(result?.title, "");
});
