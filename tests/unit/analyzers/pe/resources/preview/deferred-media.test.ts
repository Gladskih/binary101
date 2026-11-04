import assert from "node:assert/strict";
import { test } from "node:test";
import { deferLargeResourceMedia } from "../../../../../../analyzers/pe/resources/preview/deferred-media.js";
import { createPreviewLangEntry } from "../../../../../helpers/pe-resource-preview-fixture.js";
import { createFileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

void test("defers large known media using only a bounded prefix", async () => {
  const reads: number[][] = [];
  const reader = createFileRangeReader(new MockFile(new Uint8Array(32)), 0, 32);
  const mapped = { ...reader, readResourceBytes: async (rva: number, size: number) => {
    reads.push([rva, size]); return Uint8Array.of(137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0, 0, 0, 0, 0);
  } };
  const result = await deferLargeResourceMedia(mapped, "RCDATA", createPreviewLangEntry(7, 3 * 1024 * 1024));

  assert.equal(result?.preview?.previewKind, "deferred");
  assert.deepEqual(reads, [[7, 16]]);
});

void test("keeps small media, unknown binary data and invalid locations out of deferral", async () => {
  const reader = createFileRangeReader(new MockFile(new Uint8Array(32)), 0, 32);
  const size = 3 * 1024 * 1024;

  assert.equal(await deferLargeResourceMedia(reader, "BITMAP", createPreviewLangEntry(0, 2 * 1024 * 1024)), null);
  assert.equal(await deferLargeResourceMedia(reader, "RCDATA", createPreviewLangEntry(0, size)), null);
  assert.equal(await deferLargeResourceMedia(reader, "ICON", createPreviewLangEntry(0, size, 0, 1033, null)), null);
  assert.equal(await deferLargeResourceMedia(reader, "ICON", createPreviewLangEntry(0, size, 0, 1033, -1)), null);
  assert.equal(await deferLargeResourceMedia(reader, "ICON", createPreviewLangEntry(0, Infinity)), null);
  assert.equal((await deferLargeResourceMedia(reader, "FONT", createPreviewLangEntry(0, size)))?.preview?.previewKind,
    "deferred");
});

void test("lets the normal bounded reader diagnose an unreadable large media prefix", async () => {
  const reader = createFileRangeReader(new MockFile(new Uint8Array()),0,0);
  assert.equal(await deferLargeResourceMedia(reader,"BITMAP",createPreviewLangEntry(0,3*1024*1024)),null);
});
