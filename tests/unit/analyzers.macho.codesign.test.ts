"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCodeSignature } from "../../analyzers/macho/codesign.js";
import { CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE } from "../../analyzers/macho/commands.js";
import { wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

// xnu/osfmk/kern/cs_blobs.h: CSMAGIC_BLOBWRAPPER.
const BLOBWRAPPER_MAGIC = 0xfade0b01;

const writeBlobHeader = (bytes: Uint8Array, blobOffset: number, magic: number, length: number): void => {
  // CS_Blob starts with big-endian magic/u32 and length/u32.
  const view = new DataView(bytes.buffer, bytes.byteOffset + blobOffset, 8);
  view.setUint32(0, magic, false);
  view.setUint32(4, length, false);
};

const writeSuperBlob = (
  bytes: Uint8Array,
  options: {
    length: number;
    declaredCount?: number;
    entries: Array<{
      type: number;
      blobOffset: number;
    }>;
  }
): void => {
  // CS_SuperBlob extends CS_Blob with count/u32 and (type, offset) index entries.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  writeBlobHeader(bytes, 0, CSMAGIC_EMBEDDED_SIGNATURE, options.length);
  view.setUint32(8, options.declaredCount ?? options.entries.length, false);
  for (const [index, entry] of options.entries.entries()) {
    const entryOffset = 12 + index * 8;
    view.setUint32(entryOffset, entry.type, false);
    view.setUint32(entryOffset + 4, entry.blobOffset, false);
  }
};

const writeCodeDirectory = (
  bytes: Uint8Array,
  blobOffset: number,
  options: {
    length: number;
    version: number;
    flags?: number;
    hashOffset?: number;
    identOffset?: number;
    nSpecialSlots?: number;
    nCodeSlots?: number;
    codeLimit32?: number;
    hashSize?: number;
    hashType?: number;
    platform?: number;
    pageSizePower?: number;
    scatterOffset?: number;
    teamOffset?: number;
    codeLimit64?: bigint;
    execSegBase?: bigint;
    execSegLimit?: bigint;
    execSegFlags?: bigint;
    runtime?: number;
  }
): void => {
  // CS_CodeDirectory appends fields as the version grows, but the shared prefix
  // layout is fixed in xnu/osfmk/kern/cs_blobs.h.
  const view = new DataView(bytes.buffer, bytes.byteOffset + blobOffset, bytes.byteLength - blobOffset);
  writeBlobHeader(bytes, blobOffset, CSMAGIC_CODEDIRECTORY, options.length);
  view.setUint32(8, options.version, false);
  for (const [fieldOffset, value] of [
    [12, options.flags],
    [16, options.hashOffset],
    [20, options.identOffset],
    [24, options.nSpecialSlots],
    [28, options.nCodeSlots],
    [32, options.codeLimit32],
    [44, options.scatterOffset],
    [48, options.teamOffset],
    [88, options.runtime]
  ] satisfies Array<[number, number | undefined]>) {
    if (value !== undefined) view.setUint32(fieldOffset, value, false);
  }
  for (const [fieldOffset, value] of [
    [36, options.hashSize],
    [37, options.hashType],
    [38, options.platform],
    [39, options.pageSizePower]
  ] satisfies Array<[number, number | undefined]>) {
    if (value !== undefined) view.setUint8(fieldOffset, value);
  }
  for (const [fieldOffset, value] of [
    [56, options.codeLimit64],
    [64, options.execSegBase],
    [72, options.execSegLimit],
    [80, options.execSegFlags]
  ] satisfies Array<[number, bigint | undefined]>) {
    if (value !== undefined) view.setBigUint64(fieldOffset, value, false);
  }
};

void test("parseCodeSignature reports blobs that are too short for a header", async () => {
  const parsed = await parseCodeSignature(wrapMachOBytes(new Uint8Array(4), "codesign-short"), 0, 4, 0, 0, 4);
  assert.match(parsed.issues[0] || "", /too short to contain a blob header/);
});

void test("parseCodeSignature reports unexpected top-level blob magic without parsing slots", async () => {
  const bytes = new Uint8Array(8);
  writeBlobHeader(bytes, 0, CSMAGIC_CODEDIRECTORY, 8);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-cd"), 0, bytes.length, 0, 0, bytes.length);
  assert.equal(parsed.magic, CSMAGIC_CODEDIRECTORY);
  assert.equal(parsed.codeDirectory, null);
  assert.equal(parsed.slots.length, 0);
  assert.match(parsed.issues.join("\n"), /unexpected.*magic/i);
});

void test("parseCodeSignature reports truncated superblob index tables and out-of-range blobs", async () => {
  const bytes = new Uint8Array(20);
  writeSuperBlob(bytes, {
    length: bytes.length,
    declaredCount: 2,
    entries: [{ type: 0, blobOffset: 0x30 }]
  });
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-bad-index"), 0, bytes.length, 0, 0, bytes.length);
  assert.match(parsed.issues.join("\n"), /declares 2 entries but only 1 index records fit/);
  assert.match(parsed.issues.join("\n"), /points outside available data/);
});

void test("parseCodeSignature respects the declared superblob length", async () => {
  const bytes = new Uint8Array(32);
  writeSuperBlob(bytes, {
    length: 12,
    entries: [{ type: 0x10000, blobOffset: 24 }]
  });
  writeBlobHeader(bytes, 24, BLOBWRAPPER_MAGIC, 8);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-short-superblob"), 0, bytes.length, 0, 0, bytes.length);
  assert.equal(parsed.slots.length, 0);
  assert.match(parsed.issues.join("\n"), /declares 1 entries but only 0 index records fit/);
});

void test("parseCodeSignature reports truncated CodeDirectory blobs", async () => {
  const bytes = new Uint8Array(28);
  writeSuperBlob(bytes, {
    length: bytes.length,
    entries: [{ type: 0, blobOffset: 20 }]
  });
  writeBlobHeader(bytes, 20, CSMAGIC_CODEDIRECTORY, 24);
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-truncated-cd"), 0, bytes.length, 0, 0, bytes.length);
  assert.match(parsed.issues.join("\n"), /CodeDirectory blob is truncated/);
});

void test("parseCodeSignature rejects CodeDirectory string offsets that point into the fixed header", async () => {
  const values = createMachOIncidentalValues();
  const bytes = new Uint8Array(72);
  writeSuperBlob(bytes, {
    length: bytes.length,
    entries: [{ type: 0, blobOffset: 20 }]
  });
  // xnu/osfmk/kern/cs_blobs.h: CS_SUPPORTSTEAMID == 0x20200.
  writeCodeDirectory(bytes, 20, {
    length: 52,
    version: 0x20200,
    flags: values.nextUint32(),
    identOffset: 12,
    hashSize: 32,
    hashType: 2,
    pageSizePower: 12,
    teamOffset: 12
  });

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

void test("parseCodeSignature reads the 64-bit code limit starting with CodeDirectory version 0x20300", async () => {
  const values = createMachOIncidentalValues();
  const codeLimit = values.nextBigUint64();
  const bytes = new Uint8Array(88);
  writeSuperBlob(bytes, {
    length: bytes.length,
    entries: [{ type: 0, blobOffset: 20 }]
  });
  // xnu/osfmk/kern/cs_blobs.h: CS_SUPPORTSCODELIMIT64 == 0x20300.
  writeCodeDirectory(bytes, 20, {
    length: 64,
    version: 0x20300,
    hashSize: 32,
    hashType: 2,
    pageSizePower: 12,
    codeLimit64: codeLimit
  });

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-code-limit64"), 0, bytes.length, 0, 0, bytes.length);

  assert.equal(parsed.codeDirectory?.codeLimit, codeLimit);
  assert.equal(parsed.codeDirectory?.execSegBase, null);
  assert.equal(parsed.codeDirectory?.runtime, null);
});

void test("parseCodeSignature does not read CodeDirectory fields past the declared blob length", async () => {
  const values = createMachOIncidentalValues();
  const truncatedCodeLimit = values.nextUint32();
  const ignoredExecSegBase = values.nextBigUint64();
  const ignoredExecSegLimit = values.nextBigUint64();
  const ignoredExecSegFlags = values.nextBigUint64();
  const ignoredRuntime = values.nextUint32();
  const bytes = new Uint8Array(120);
  writeSuperBlob(bytes, { length: bytes.length, entries: [{ type: 0, blobOffset: 20 }] });
  // xnu/osfmk/kern/cs_blobs.h: runtime fields arrive in CodeDirectory version 0x20500.
  writeCodeDirectory(bytes, 20, {
    length: 44,
    version: 0x20500,
    codeLimit32: truncatedCodeLimit,
    hashSize: 32,
    hashType: 2,
    pageSizePower: 12,
    execSegBase: ignoredExecSegBase,
    execSegLimit: ignoredExecSegLimit,
    execSegFlags: ignoredExecSegFlags,
    runtime: ignoredRuntime
  });
  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-version-truncated"), 0, bytes.length, 0, 0, bytes.length);
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
  writeSuperBlob(bytes, {
    length: 116,
    entries: [{ type: 0, blobOffset: 20 }]
  });
  // xnu/osfmk/kern/cs_blobs.h: runtime fields arrive in CodeDirectory version 0x20500.
  writeCodeDirectory(bytes, 20, {
    length: 96,
    version: 0x20500,
    nSpecialSlots: 1,
    nCodeSlots: 2,
    codeLimit32: Number(codeLimit & 0xffff_ffffn),
    hashSize: 32,
    hashType: 2,
    pageSizePower: 12,
    codeLimit64: codeLimit,
    execSegBase,
    execSegLimit,
    execSegFlags,
    runtime: runtimeVersion
  });

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-runtime"), 0, bytes.length, 0, 0, bytes.length);

  assert.equal(parsed.codeDirectory?.codeLimit, codeLimit);
  assert.equal(parsed.codeDirectory?.execSegBase, execSegBase);
  assert.equal(parsed.codeDirectory?.execSegLimit, execSegLimit);
  assert.equal(parsed.codeDirectory?.execSegFlags, execSegFlags);
  assert.equal(parsed.codeDirectory?.runtime, runtimeVersion);
});

void test("parseCodeSignature reports code-sign data and superblob lengths that exceed the image", async () => {
  const bytes = new Uint8Array(16);
  writeSuperBlob(bytes, { length: 32, entries: [] });

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-overflow"), 0, bytes.length, 0, 0, 32);

  assert.match(parsed.issues.join("\n"), /Code-signing data extends beyond the Mach-O image/);
  assert.match(parsed.issues.join("\n"), /Code-signing superblob length exceeds available data/);
});

void test("parseCodeSignature reports truncated superblob headers after the blob header", async () => {
  const bytes = new Uint8Array(10);
  writeBlobHeader(bytes, 0, CSMAGIC_EMBEDDED_SIGNATURE, bytes.length);

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-short-superblob-header"), 0, bytes.length, 0, 0, bytes.length);

  assert.match(parsed.issues.join("\n"), /Code-signing superblob is truncated/);
});

void test("parseCodeSignature reports embedded blobs that declare less than a header", async () => {
  const bytes = new Uint8Array(28);
  writeSuperBlob(bytes, {
    length: bytes.length,
    entries: [{ type: 0x10000, blobOffset: 20 }]
  });
  writeBlobHeader(bytes, 20, BLOBWRAPPER_MAGIC, 4);

  const parsed = await parseCodeSignature(wrapMachOBytes(bytes, "codesign-short-blob"), 0, bytes.length, 0, 0, bytes.length);

  assert.match(parsed.issues.join("\n"), /declares length 4 smaller than a blob header/);
});
