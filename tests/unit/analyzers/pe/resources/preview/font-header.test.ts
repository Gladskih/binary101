import assert from "node:assert/strict";
import { test } from "node:test";
import { readFontHeader, readFontName } from "../../../../../../analyzers/pe/resources/preview/font-header.js";
import { buildLegacyFont } from "../../../../../fixtures/pe-font-resources.js";

void test("rejects invalid header offsets and truncation", () => {
  const data = buildLegacyFont();
  assert.equal(readFontHeader(data, -1), null);
  assert.equal(readFontHeader(data, NaN), null);
  assert.equal(readFontHeader(data, 0.5), null);
  assert.equal(readFontHeader(data, Number.MAX_SAFE_INTEGER), null);
  assert.equal(readFontHeader(data.subarray(0, 112), 0), null);
  assert.equal(readFontHeader(data, 0)?.copyright, "Fixture copyright");
  data.fill(65, 6, 66);
  assert.equal(readFontHeader(data, 0)?.copyright, "A".repeat(60));
});

void test("bounds names and reports missing terminators and uncertain ANSI decoding", () => {
  const data = new Uint8Array([65, 0, 0x80]);
  const issues: string[] = [];
  assert.deepEqual(readFontName(data, 0, issues), { text: "A", nextOffset: 2 });
  assert.deepEqual(readFontName(data, 2, issues), { text: "€", nextOffset: 3 });
  assert.equal(readFontName(data, -1, issues).text, "");
  assert.equal(readFontName(data, NaN, issues).text, "");
  assert.equal(readFontName(data, 3, issues).text, "");
  assert.equal(issues.length, 5);
});
