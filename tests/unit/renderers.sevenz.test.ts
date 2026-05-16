"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSevenZip } from "../../renderers/sevenz/index.js";
import type { SevenZipParseResult } from "../../analyzers/sevenz/index.js";

const createSevenZipResult = (): SevenZipParseResult => ({
  is7z: true,
  issues: ["Notice"],
  startHeader: {
    versionMajor: 0,
    versionMinor: 4,
    startHeaderCrc: 0,
    nextHeaderOffset: 0n,
    nextHeaderSize: 2n,
    nextHeaderCrc: 0,
    absoluteNextHeaderOffset: 32n
  },
  nextHeader: { offset: 32n, size: 2n, crc: 0, parsed: { kind: "encoded", headerStreams: {}, headerCoders: [], hasEncryptedHeader: false } },
  headerEncoding: {
    coders: [{
      index: 0,
      isEncrypted: false,
      coders: [{ id: "LZMA", methodId: "030101", numInStreams: 1, numOutStreams: 1, properties: null, isEncryption: false }]
    }],
    hasEncryptedHeader: false
  },
  structure: {
    archiveFlags: { isSolid: false, isHeaderEncrypted: false, hasEncryptedContent: false },
    folders: [{
      index: 0,
      unpackSize: 4n,
      packedSize: 14n,
      packedOffset: 32n,
      coders: [{ id: "LZMA", methodId: "030101", numInStreams: 1, numOutStreams: 1, properties: null, isEncryption: false }],
      numUnpackStreams: 1,
      substreams: [{ size: 4n, crc: null }],
      isEncrypted: false
    }],
    files: [
      {
        index: 0,
        name: "ok.bin",
        folderIndex: 0,
        folderStreamIndex: 0,
        uncompressedSize: 4n,
        packedSize: 14n,
        compressionRatio: 350,
        crc32: 0x12345678,
        modifiedTime: null,
        attributes: null,
        hasStream: true,
        isDirectory: false
      },
      {
        index: 1,
        name: "unsupported.bin",
        folderIndex: 0,
        folderStreamIndex: 0,
        uncompressedSize: 4n,
        packedSize: 14n,
        compressionRatio: 350,
        crc32: null,
        modifiedTime: null,
        attributes: null,
        hasStream: true,
        isDirectory: false,
        extractError: "Unsupported coder."
      }
    ]
  }
});

void test("renderSevenZip shows encoded header details and extraction actions", () => {
  const html = renderSevenZip(createSevenZipResult());

  assert.match(html, /Header encoding/);
  assert.match(html, /header streams appear compressed but not encrypted/);
  assert.match(html, /data-sevenzip-entry="0"/);
  assert.match(html, /Unsupported coder\./);
  assert.match(html, /Notice/);
  assert.match(html, /12345678/);
});

void test("renderSevenZip returns an empty string for non-7z results", () => {
  assert.equal(renderSevenZip(null), "");
  assert.equal(renderSevenZip({ is7z: false, issues: [] }), "");
});
