"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import { parseFb2 } from "../../dist/analyzers/fb2/index.js";
import { createFb2File } from "../fixtures/sample-files.js";
import { MockFile } from "../helpers/mock-file.js";

class TestDomParser extends XmlDomParser {
  parseFromString(text, type) {
    const doc = super.parseFromString(text, type);
    if (!doc.querySelector) {
      doc.querySelector = selector => {
        const tagName = selector.replace(/[^a-zA-Z0-9:-]/g, "");
        const matches = doc.getElementsByTagName(tagName);
        return matches && matches.length ? matches[0] : null;
      };
    }
    return doc;
  }
}

global.DOMParser = TestDomParser;

const encoder = new TextEncoder();

test("parseFb2 skips files without FictionBook root", async () => {
  const file = new MockFile(encoder.encode("<root></root>"), "note.xml", "text/xml");
  const result = await parseFb2(file);
  assert.strictEqual(result, null);
});

test("parseFb2 returns structured metadata for valid FB2", async () => {
  const fb2 = await parseFb2(createFb2File());
  assert.ok(fb2);
  assert.strictEqual(fb2?.title, "Example");
  assert.strictEqual(fb2?.publishInfo.publisher, "");
  assert.strictEqual(fb2?.parseError, false);
  assert.ok(fb2?.bodyCount >= 1);
});

test("parseFb2 truncates long annotations and reads sequence", async () => {
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
  const fb2 = await parseFb2(new MockFile(encoder.encode(xml), "annotated.fb2", "text/xml"));
  assert.ok(fb2);
  assert.strictEqual(fb2?.title, "Annotated");
  assert.ok(fb2?.annotation);
  assert.ok(fb2?.annotation?.endsWith("..."));
  assert.deepStrictEqual(fb2?.sequence, { name: "Saga", number: "2" });
});
