"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRar } from "../../../../analyzers/rar/index.js";
import { createRar4File, createRar5File } from "../../../fixtures/rar-sevenzip-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createSliceTrackingFile } from "../../../helpers/slice-tracking-file.js";

const withTrailingJunk = (archive: Uint8Array): MockFile => {
  const bytes = new Uint8Array(archive.byteLength + 16);
  bytes.set(archive);
  bytes.fill(0xff, archive.byteLength);
  return new MockFile(bytes, "archive-with-junk.rar");
};

void test("parseRar4 stops at the end-of-archive header", async () => {
  const result = await parseRar(withTrailingJunk(createRar4File().data));

  assert.ok(result.endHeader);
  assert.deepEqual(result.issues, []);
});

void test("parseRar5 stops at the end-of-archive header", async () => {
  const baseline = await parseRar(createRar5File());
  const result = await parseRar(withTrailingJunk(createRar5File().data));

  assert.ok(result.endHeader);
  assert.deepEqual(result.issues, baseline.issues);
});

void test("parseRar5 keeps every byte of a file name after its header-size vint", async () => {
  const result = await parseRar(createRar5File());

  assert.equal(result.entries[0]?.name, "note.txt");
  assert.deepEqual(result.issues, []);
});

void test("parseRar5 reuses one cached range for adjacent headers", async () => {
  const archive = createRar5File().data;
  const tracked = createSliceTrackingFile(archive, archive.byteLength, "cached-headers.rar");

  const result = await parseRar(tracked.file);

  assert.equal(result.entries.length, 1);
  assert.deepEqual(tracked.requests, [archive.byteLength]);
});
