"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { archiveProbes } from "../../analyzers/probes/magic-archives.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => archiveProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;

void test("detects common archive signatures", () => {
  assert.strictEqual(run([0x50, 0x4b, 0x03, 0x04]), "ZIP archive (PK-based, e.g. Office, JAR, APK)");
  assert.strictEqual(run([0x1f, 0x8b]), "gzip compressed data");
  assert.strictEqual(run([0x42, 0x5a, 0x68]), "bzip2 compressed data");
  assert.strictEqual(run([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), "7z archive");
  assert.strictEqual(run([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), "XZ compressed data");
  assert.strictEqual(run([0x04, 0x22, 0x4d, 0x18]), "LZ4 frame");
  assert.strictEqual(run([0x28, 0xb5, 0x2f, 0xfd]), "Zstandard compressed data (zstd)");
  assert.strictEqual(run([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]), "RAR archive");
  assert.strictEqual(run([0x4d, 0x53, 0x43, 0x46]), "Microsoft Cabinet archive (CAB)");
});

void test("detects TAR and ISO-9660 at expected offsets", () => {
  const tar = new Uint8Array(300).fill(0);
  tar.set([0x75, 0x73, 0x74, 0x61, 0x72], 257);
  assert.strictEqual(run(tar), "TAR archive");

  const iso = new Uint8Array(0x9010).fill(0);
  iso.set([0x43, 0x44, 0x30, 0x30, 0x31], 0x9001);
  assert.strictEqual(run(iso), "ISO-9660 CD/DVD image (ISO)");
});

void test("returns null for short or unknown data", () => {
  assert.strictEqual(run([]), null);
  assert.strictEqual(run([0x00, 0x01, 0x02, 0x03]), null);
});
