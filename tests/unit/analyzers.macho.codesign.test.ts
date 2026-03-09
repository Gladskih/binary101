"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCodeSignature } from "../../analyzers/macho/codesign.js";
import { wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

// xnu/osfmk/kern/cs_blobs.h: CSMAGIC_CODEDIRECTORY and CSMAGIC_EMBEDDED_SIGNATURE.
const CODEDIRECTORY_MAGIC = 0xfade0c02;
const EMBEDDED_SIGNATURE_MAGIC = 0xfade0cc0;

void test("parseCodeSignature reports blobs that are too short for a header", async () => {
  const parsed = await parseCodeSignature(wrapMachOBytes(new Uint8Array(4), "codesign-short"), 0, 4, 0, 0, 4);
  assert.match(parsed.issues[0] || "", /too short to contain a blob header/);
});

void test("parseCodeSignature preserves non-superblob headers without parsing slots", async () => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CODEDIRECTORY_MAGIC, false);
  view.setUint32(4, 8, false);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-cd"), 0, bytes.length, 0, 0, bytes.length);
  assert.equal(parsed.magic, CODEDIRECTORY_MAGIC);
  assert.equal(parsed.codeDirectory, null);
  assert.equal(parsed.slots.length, 0);
});

void test("parseCodeSignature reports truncated superblob index tables and out-of-range blobs", async () => {
  const bytes = new Uint8Array(20);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
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
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
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
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, CODEDIRECTORY_MAGIC, false);
  view.setUint32(24, 24, false);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-truncated-cd"), 0, bytes.length, 0, 0, bytes.length);
  assert.match(parsed.issues.join("\n"), /CodeDirectory blob is truncated/);
});

void test("parseCodeSignature rejects CodeDirectory string offsets that point into the fixed header", async () => {
  const values = createMachOIncidentalValues();
  const bytes = new Uint8Array(72);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, CODEDIRECTORY_MAGIC, false);
  view.setUint32(24, 52, false);
  // xnu/osfmk/kern/cs_blobs.h: CS_SUPPORTSTEAMID == 0x20200.
  view.setUint32(28, 0x20200, false);
  view.setUint32(32, values.nextUint32(), false);
  view.setUint32(40, 12, false);
  view.setUint8(56, 32);
  view.setUint8(57, 2);
  view.setUint8(59, 12);
  view.setUint32(68, 12, false);

  const parsed = await parseCodeSignature(
    wrapMachOBytes(bytes, "codesign-header-string-offset"),
    0,
    bytes.length,
    0,
    0,
    bytes.length
  );

  assert.equal(parsed.codeDirectory?.identifier, null);
  assert.equal(parsed.codeDirectory?.teamIdentifier, null);
  assert.match(parsed.issues.join("\n"), /identifier offset 12 points inside the fixed header/i);
  assert.match(parsed.issues.join("\n"), /team identifier offset 12 points inside the fixed header/i);
});

void test("parseCodeSignature does not read CodeDirectory fields past the declared blob length", async () => {
  const values = createMachOIncidentalValues();
  const truncatedCodeLimit = values.nextUint32();
  const ignoredExecSegBase = values.nextBigUint64();
  const ignoredExecSegLimit = values.nextBigUint64();
  const ignoredExecSegFlags = values.nextBigUint64();
  const ignoredRuntime = values.nextUint32();
  const bytes = new Uint8Array(120);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, CODEDIRECTORY_MAGIC, false);
  view.setUint32(24, 44, false);
  // CodeDirectory version 0x20500 is the first one with 64-bit code-limit fields.
  view.setUint32(28, 0x20500, false);
  view.setUint32(40, 0, false);
  view.setUint32(44, 0, false);
  view.setUint32(48, 0, false);
  view.setUint32(52, truncatedCodeLimit, false);
  view.setUint8(56, 32);
  view.setUint8(57, 2);
  view.setUint8(58, 0);
  view.setUint8(59, 12);
  view.setBigUint64(76, ignoredExecSegBase, false);
  view.setBigUint64(84, ignoredExecSegLimit, false);
  view.setBigUint64(92, ignoredExecSegFlags, false);
  view.setUint32(108, ignoredRuntime, false);
  const parsed = await parseCodeSignature(
    wrapMachOBytes(bytes, "codesign-version-truncated"),
    0,
    bytes.length,
    0,
    0,
    bytes.length
  );
  assert.equal(parsed.codeDirectory?.codeLimit, BigInt(truncatedCodeLimit));
  assert.equal(parsed.codeDirectory?.execSegBase, null);
  assert.equal(parsed.codeDirectory?.runtime, null);
  assert.match(parsed.issues.join("\n"), /truncated before the 64-bit code limit/);
});

void test("parseCodeSignature reads runtime and exec segment fields from complete CodeDirectory blobs", async () => {
  const values = createMachOIncidentalValues();
  const codeLimit = values.nextBigUint64();
  const execSegBase = values.nextBigUint64();
  const execSegLimit = values.nextBigUint64();
  const execSegFlags = BigInt((values.nextUint8() & 0x07) + 1);
  const runtimeVersion = (values.nextUint8() & 0x07) + 1;
  const bytes = new Uint8Array(120);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, 116, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, CODEDIRECTORY_MAGIC, false);
  view.setUint32(24, 96, false);
  // CodeDirectory version 0x20500 is the first one with 64-bit code-limit fields.
  view.setUint32(28, 0x20500, false);
  view.setUint32(40, 1, false);
  view.setUint32(44, 2, false);
  view.setUint32(48, Number(codeLimit & 0xffff_ffffn), false);
  view.setUint8(56, 32);
  view.setUint8(57, 2);
  view.setUint8(59, 12);
  view.setBigUint64(76, codeLimit, false);
  view.setBigUint64(84, execSegBase, false);
  view.setBigUint64(92, execSegLimit, false);
  view.setBigUint64(100, execSegFlags, false);
  view.setUint32(108, runtimeVersion, false);

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-runtime"), 0, bytes.length, 0, 0, bytes.length);

  assert.equal(parsed.codeDirectory?.codeLimit, codeLimit);
  assert.equal(parsed.codeDirectory?.execSegBase, execSegBase);
  assert.equal(parsed.codeDirectory?.execSegLimit, execSegLimit);
  assert.equal(parsed.codeDirectory?.execSegFlags, execSegFlags);
  assert.equal(parsed.codeDirectory?.runtime, runtimeVersion);
});

void test("parseCodeSignature reports code-sign data and superblob lengths that exceed the image", async () => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, 32, false);
  view.setUint32(8, 0, false);

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-overflow"), 0, bytes.length, 0, 0, 32);

  assert.match(parsed.issues.join("\n"), /Code-signing data extends beyond the Mach-O image/);
  assert.match(parsed.issues.join("\n"), /Code-signing superblob length exceeds available data/);
});

void test("parseCodeSignature reports truncated superblob headers after the blob header", async () => {
  const bytes = new Uint8Array(10);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, bytes.length, false);

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-short-superblob-header"), 0, bytes.length, 0, 0, bytes.length);

  assert.match(parsed.issues.join("\n"), /Code-signing superblob is truncated/);
});

void test("parseCodeSignature reports embedded blobs that declare less than a header", async () => {
  const bytes = new Uint8Array(28);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EMBEDDED_SIGNATURE_MAGIC, false);
  view.setUint32(4, bytes.length, false);
  view.setUint32(8, 1, false);
  view.setUint32(12, 0x10000, false);
  view.setUint32(16, 20, false);
  view.setUint32(20, 0xfade0b01, false);
  view.setUint32(24, 4, false);

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-short-blob"), 0, bytes.length, 0, 0, bytes.length);

  assert.match(parsed.issues.join("\n"), /declares length 4 smaller than a blob header/);
});
