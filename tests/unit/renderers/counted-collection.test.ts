import assert from "node:assert/strict";
import { test } from "node:test";
import { renderCollectionStart, renderCollectionEnd, renderCountedCollection } from
  "../../../renderers/counted-collection.js";

void test("one record is immediately visible and has no disclosure control", () => {
  const html = renderCountedCollection("Records (1)", "<p>record</p>", 1);

  assert.match(html, /<h5 class="collectionSummary">Records \(1\)<\/h5><p>record<\/p>/);
  assert.doesNotMatch(html, /<details|<summary/);
  assert.equal(html, '<section><h5 class="collectionSummary">Records (1)</h5><p>record</p></section>');
  assert.equal(renderCollectionEnd(1), "</section>");
  assert.equal(renderCollectionEnd(2), "</details>");
});

void test("multiple records keep native disclosure and container identity", () => {
  const html = renderCountedCollection("Records (2)", "<p>records</p>", 2, ' data-test="records"');

  assert.match(html, /^<details data-test="records"><summary/);
  assert.match(html, /records<\/p><\/details>$/);
});

void test("a single record preserves its container attributes", () => {
  assert.match(renderCountedCollection("Record", "value", 1, ' class="record"'), /^<section class="record">/);
});

void test("empty, negative, fractional and unknown collection sizes do not create empty controls", () => {
  assert.equal(renderCountedCollection("Empty", "", 0), "");
  assert.equal(renderCountedCollection("Invalid", "", -1), "");
  assert.equal(renderCountedCollection("Invalid", "", 0.5), "");
  assert.equal(renderCountedCollection("Invalid", "", Number.NaN), "");
  assert.equal(renderCountedCollection("Invalid", "not a valid record", -1), "");
  assert.equal(renderCountedCollection("Empty", "not a valid record", 0), "");
  assert.equal(renderCollectionStart("Empty", 0), "");
  assert.equal(renderCollectionEnd(0), "");
  assert.equal(renderCollectionEnd(-1), "");
});
