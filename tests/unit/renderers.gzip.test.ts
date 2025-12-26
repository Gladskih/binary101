"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseGzip } from "../../analyzers/gzip/index.js";
import { renderGzip } from "../../renderers/gzip/index.js";
import { createGzipFile, createTruncatedGzipFile } from "../fixtures/gzip-fixtures.js";
import { encoder } from "../fixtures/archive-fixture-helpers.js";

void test("renderGzip renders header and trailer summary", async () => {
  const payload = encoder.encode("hello");
  const parsed = await parseGzip(createGzipFile({ payload }));
  assert.ok(parsed);
  const html = renderGzip(parsed);
  assert.match(html, /gzip/i);
  assert.match(html, /Header/i);
  assert.match(html, /Trailer/i);
});

void test("renderGzip omits optional sections when fields are absent", async () => {
  const payload = encoder.encode("hello");
  const parsed = await parseGzip(
    createGzipFile({ payload, extra: null, filename: null, comment: null, includeHeaderCrc16: false })
  );
  assert.ok(parsed);
  const html = renderGzip(parsed);
  assert.doesNotMatch(html, /<dt>Extra field<\/dt>/);
  assert.match(html, /Original filename/);
  assert.match(html, /Comment/);
});

void test("renderGzip renders truncation and reserved-flag notices", async () => {
  const payload = encoder.encode("hello");
  const reserved = await parseGzip(createGzipFile({ payload, reservedFlagBits: 0xe0 }));
  assert.ok(reserved);
  assert.match(renderGzip(reserved), /Reserved flag bits/);

  const truncated = await parseGzip(createTruncatedGzipFile());
  assert.ok(truncated);
  const html = renderGzip(truncated);
  assert.match(html, /Header truncated/);
  assert.match(html, /Trailer truncated/);
  assert.match(html, /File truncated/);
});
