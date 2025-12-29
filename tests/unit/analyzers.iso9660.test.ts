"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseIso9660 } from "../../analyzers/iso9660/index.js";
import { createIso9660JolietFile, createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseIso9660 parses a primary volume and root directory entries", async () => {
  const file = createIso9660PrimaryFile();
  const parsed = await parseIso9660(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.isIso9660, true);
  assert.strictEqual(parsed.selectedEncoding, "ascii");
  assert.ok(parsed.primaryVolume);
  assert.strictEqual(parsed.primaryVolume.volumeIdentifier, "TESTVOL");
  assert.strictEqual(parsed.primaryVolume.logicalBlockSize, 2048);
  assert.ok(parsed.pathTable);
  assert.strictEqual(parsed.pathTable.entryCount, 1);
  const firstPathEntry = parsed.pathTable.entries[0];
  assert.ok(firstPathEntry);
  assert.strictEqual(firstPathEntry.identifier, "/");
  assert.ok(parsed.rootDirectory);
  assert.strictEqual(parsed.rootDirectory.totalEntries, 4);
  assert.ok(parsed.rootDirectory.entries.some(e => e.name === "HELLO.TXT"));
  assert.ok(parsed.rootDirectory.entries.some(e => e.name === "SUBDIR"));
  assert.ok(parsed.traversal);
  assert.strictEqual(parsed.traversal.scannedDirectories, 2);
  assert.strictEqual(parsed.traversal.scannedFiles, 2);
});

void test("parseIso9660 prefers Joliet supplementary descriptors when present", async () => {
  const file = createIso9660JolietFile();
  const parsed = await parseIso9660(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.selectedEncoding, "ucs2be");
  assert.ok(parsed.supplementaryVolumes.some(svd => svd.isJoliet));
  assert.ok(parsed.bootRecords.length >= 1);
  const firstBootRecord = parsed.bootRecords[0];
  assert.ok(firstBootRecord);
  assert.strictEqual(firstBootRecord.elToritoCatalogLba, 40);
  assert.ok(parsed.rootDirectory);
  assert.ok(parsed.rootDirectory.entries.some(e => e.name === "A.TXT"));
});

void test("parseIso9660 returns null when the volume descriptor does not match ISO-9660", async () => {
  const bytes = new Uint8Array(2048 * 20).fill(0);
  const file = new MockFile(bytes, "not-iso.bin", "application/octet-stream");
  const parsed = await parseIso9660(file);
  assert.equal(parsed, null);
});
