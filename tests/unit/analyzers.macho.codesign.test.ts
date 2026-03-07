"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE
} from "../../analyzers/macho/commands.js";
import { parseCodeSignature } from "../../analyzers/macho/codesign.js";
import { wrapMachOBytes } from "../fixtures/macho-fixtures.js";

void test("parseCodeSignature reports blobs that are too short for a header", async () => {
  const parsed = await parseCodeSignature(wrapMachOBytes(new Uint8Array(4), "codesign-short"), 0, 4, 0, 0, 4);
  assert.match(parsed.issues[0] || "", /too short to contain a blob header/);
});

void test("parseCodeSignature preserves non-superblob headers without parsing slots", async () => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CSMAGIC_CODEDIRECTORY, false);
  view.setUint32(4, 8, false);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-cd"), 0, bytes.length, 0, 0, bytes.length);
  assert.equal(parsed.magic, CSMAGIC_CODEDIRECTORY);
  assert.equal(parsed.codeDirectory, null);
  assert.equal(parsed.slots.length, 0);
});

void test("parseCodeSignature reports truncated superblob index tables and out-of-range blobs", async () => {
  const bytes = new Uint8Array(20);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CSMAGIC_EMBEDDED_SIGNATURE, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 2, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 0x30, false);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-bad-index"), 0, bytes.length, 0, 0, bytes.length);
  assert.match(parsed.issues.join("\n"), /declares 2 entries but only 1 index records fit/);
  assert.match(parsed.issues.join("\n"), /points outside available data/);
});

void test("parseCodeSignature reports truncated CodeDirectory blobs", async () => {
  const bytes = new Uint8Array(28);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CSMAGIC_EMBEDDED_SIGNATURE, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, CSMAGIC_CODEDIRECTORY, false);
  view.setUint32(24, 24, false);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-truncated-cd"), 0, bytes.length, 0, 0, bytes.length);
  assert.match(parsed.issues.join("\n"), /CodeDirectory blob is truncated/);
});
