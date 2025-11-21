"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { hasSevenZipSignature, parseSevenZip } from "../../analyzers/sevenz/index.js";
import { MockFile } from "../helpers/mock-file.mjs";

const SIGNATURE = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];

const buildStartHeader = (nextHeaderLength, nextHeaderOffset = 0n) => {
  const header = new Uint8Array(32).fill(0);
  header.set(SIGNATURE, 0);
  const view = new DataView(header.buffer);
  view.setUint8(6, 0);
  view.setUint8(7, 4);
  view.setBigUint64(12, nextHeaderOffset, true);
  view.setBigUint64(20, BigInt(nextHeaderLength), true);
  return header;
};

const buildSevenZipFile = nextHeaderBytes => {
  const startHeader = buildStartHeader(nextHeaderBytes.length);
  const bytes = new Uint8Array(startHeader.length + nextHeaderBytes.length);
  bytes.set(startHeader, 0);
  bytes.set(nextHeaderBytes, startHeader.length);
  return new MockFile(bytes, "custom.7z", "application/x-7z-compressed");
};

const toFileTime = unixSeconds =>
  (BigInt(unixSeconds) + 11644473600n) * 10000000n;

const buildStructuredHeader = () => {
  const streamsInfo = [
    0x06, // PackInfo
    0x00, // packPos
    0x01, // numPackStreams
    0x09, // packSizes id
    0x05, // pack size
    0x00, // end PackInfo
    0x07, // UnpackInfo
    0x0b, // folder id
    0x01, // numFolders
    0x00, // external flag
    0x01, // coder count
    0x01, // coder flags (1 byte id, simple, no properties)
    0x21, // method id (LZMA2)
    0x0c, // sizes id
    0x05, // unpack size
    0x00, // crc marker reused as end marker
    0x00 // end StreamsInfo
  ];

  const names = Buffer.from("file1\u0000folder\u0000", "utf16le");
  const namesSize = 1 + names.length; // external flag + names
  const times = new Uint8Array(16);
  const timesView = new DataView(times.buffer);
  timesView.setBigUint64(0, toFileTime(1_700_000_000n), true);
  timesView.setBigUint64(8, toFileTime(1_700_000_500n), true);

  const attrs = new Uint8Array(8);
  const attrView = new DataView(attrs.buffer);
  attrView.setUint32(0, 0x20, true); // archive
  attrView.setUint32(4, 0x10, true); // directory

  const filesInfo = [
    0x02, // file count
    0x0e, // Empty streams
    0x02, // size
    0x00, // allDefined flag
    0x02, // flags (second file is empty stream)
    0x0f, // Empty files
    0x02, // size
    0x00, // allDefined flag
    0x02, // flags (second file empty file)
    0x11, // Names
    namesSize,
    0x00, // internal (not external)
    ...names,
    0x14, // Modification times
    0x13, // size (19 bytes)
    0x00, // external flag
    0x00, // allDefined flag
    0x03, // flags for two files
    ...times,
    0x15, // Attributes
    0x0b, // size (11 bytes)
    0x00, // external flag
    0x00, // allDefined flag
    0x03, // flags for two files
    ...attrs,
    0x00 // end FilesInfo
  ];

  return new Uint8Array([0x01, 0x04, ...streamsInfo, 0x05, ...filesInfo, 0x00]);
};

const buildEncodedHeader = () =>
  new Uint8Array([
    0x17, // encoded header marker
    0x07, // StreamsInfo -> UnpackInfo
    0x0b,
    0x01, // one folder
    0x00, // internal
    0x01, // coder count
    0x04, // coder flags: 4-byte id
    0x06, 0xf1, 0x07, 0x01, // AES-256 method id
    0x0c, // unpack sizes id
    0x01, // unpack size
    0x00, // crc marker reused as end
    0x00 // end StreamsInfo
  ]);

test("hasSevenZipSignature detects 7z magic bytes", () => {
  const sig = new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]);
  assert.equal(hasSevenZipSignature(new DataView(sig.buffer)), true);
  assert.equal(hasSevenZipSignature(new DataView(new Uint8Array([0x00, 0x01]).buffer)), false);
});

test("parseSevenZip reports out-of-bounds next header", async () => {
  const header = new Uint8Array(48).fill(0);
  header.set([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], 0);
  header[6] = 0; // version major
  header[7] = 4; // version minor
  // startHeaderCrc (ignored here)
  header[8] = 0x12;
  header[9] = 0x34;
  header[10] = 0x56;
  header[11] = 0x78;
  // nextHeaderOffset = 8
  header[12] = 8;
  // nextHeaderSize = 16
  header[20] = 16;
  // nextHeaderCrc
  header[28] = 0xaa;
  header[29] = 0xbb;
  header[30] = 0xcc;
  header[31] = 0xdd;

  const file = new MockFile(header, "bad-next-header.7z");
  const parsed = await parseSevenZip(file);
  assert.equal(parsed.is7z, true);
  assert.ok(parsed.issues.some(msg => msg.includes("outside the file bounds")));
});

test("parseSevenZip returns non-7z for missing signature", async () => {
  const file = new MockFile(new Uint8Array(16).fill(0), "not7z.bin");
  const parsed = await parseSevenZip(file);
  assert.equal(parsed.is7z, false);
});

test("parseSevenZip builds folder and file structures from header", async () => {
  const archive = buildSevenZipFile(buildStructuredHeader());
  const parsed = await parseSevenZip(archive);
  assert.equal(parsed.is7z, true);
  assert.strictEqual(parsed.issues.length, 0);
  assert.ok(parsed.structure);
  assert.strictEqual(parsed.structure.folders.length, 1);
  assert.strictEqual(parsed.structure.folders[0].coders[0].id, "LZMA2");
  assert.strictEqual(parsed.structure.files.length, 2);
  assert.strictEqual(parsed.structure.files[0].name, "file1");
  assert.strictEqual(parsed.structure.files[0].folderIndex, 0);
  assert.strictEqual(parsed.structure.files[0].compressionRatio, 100);
  assert.strictEqual(parsed.structure.files[1].isDirectory, true);
  assert.ok(parsed.structure.files[0].modifiedTime);
});

test("parseSevenZip reports encoded headers and encryption markers", async () => {
  const encryptedHeader = buildSevenZipFile(buildEncodedHeader());
  const parsed = await parseSevenZip(encryptedHeader);
  assert.equal(parsed.is7z, true);
  assert.strictEqual(parsed.nextHeader.parsed.kind, "encoded");
  assert.ok(parsed.headerEncoding);
  assert.strictEqual(parsed.headerEncoding.hasEncryptedHeader, true);
  assert.ok(
    parsed.headerEncoding.coders.some(folder =>
      folder.coders.some(coder => coder.id === "AES-256")
    )
  );
});
