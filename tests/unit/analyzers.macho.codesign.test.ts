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

void test("parseCodeSignature respects the declared superblob length", async () => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CSMAGIC_EMBEDDED_SIGNATURE, false);
  view.setUint32(4, 12, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0x10000, false);
  view.setUint32(16, 24, false);
  view.setUint32(24, 0xfade0b01, false);
  view.setUint32(28, 8, false);
  const parsed = await parseCodeSignature(
    wrapMachOBytes(bytes, "codesign-short-superblob"),
    0,
    bytes.length,
    0,
    0,
    bytes.length
  );
  assert.equal(parsed.slots.length, 0);
  assert.match(parsed.issues.join("\n"), /declares 1 entries but only 0 index records fit/);
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

void test("parseCodeSignature does not read CodeDirectory fields past the declared blob length", async () => {
  const bytes = new Uint8Array(120);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CSMAGIC_EMBEDDED_SIGNATURE, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, CSMAGIC_CODEDIRECTORY, false);
  view.setUint32(24, 44, false);
  view.setUint32(28, 0x20500, false);
  view.setUint32(40, 0, false);
  view.setUint32(44, 0, false);
  view.setUint32(48, 0, false);
  view.setUint32(52, 0x11111111, false);
  view.setUint8(56, 32);
  view.setUint8(57, 2);
  view.setUint8(58, 0);
  view.setUint8(59, 12);
  view.setBigUint64(76, 0x2222222222222222n, false);
  view.setBigUint64(84, 0x3333333333333333n, false);
  view.setBigUint64(92, 0x4444444444444444n, false);
  view.setUint32(108, 0x55555555, false);
  const parsed = await parseCodeSignature(
    wrapMachOBytes(bytes, "codesign-version-truncated"),
    0,
    bytes.length,
    0,
    0,
    bytes.length
  );
  assert.equal(parsed.codeDirectory?.codeLimit, 0x11111111n);
  assert.equal(parsed.codeDirectory?.execSegBase, null);
  assert.equal(parsed.codeDirectory?.runtime, null);
  assert.match(parsed.issues.join("\n"), /truncated before the 64-bit code limit/);
});
