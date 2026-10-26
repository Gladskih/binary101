"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeEncodedHeader } from "../../../../analyzers/sevenz/encoded-header.js";
import { SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER } from "../../../../analyzers/sevenz/layout.js";
import { SEVENZIP_LZMA_METHOD_ID } from "../../../../analyzers/sevenz/method-ids.js";
import type { SevenZipParsedNextHeader } from "../../../../analyzers/sevenz/types.js";
import { crc32 } from "../../../../analyzers/crc32.js";
import { MockFile } from "../../../helpers/mock-file.js";

const EMPTY_HEADER_UNPACK_SIZE = 2n;
const PACK_POSITION_AT_ARCHIVE_START = 0n;
const SINGLE_STREAM_COUNT = 1;
const NO_BIND_PAIRS = 0;
// 7z LZMA coder properties for lc=3, lp=0, pb=2 and a 64 KiB dictionary.
// https://www.7-zip.org/sdk.html
const LZMA_PROPERTIES = [0x5d, 0x00, 0x00, 0x01, 0x00];
// Raw LZMA stream fixture that decodes to a minimal Header payload [0x01, 0x00].
// The raw decoder receives the 7z properties separately, with no LZMA-alone wrapper.
const PACKED_EMPTY_HEADER = Uint8Array.from([
  0x00, 0x00, 0x80, 0x25, 0xa5, 0xef, 0xff, 0xff, 0xec, 0xc7, 0x00, 0x00
]);

const createEncodedHeader = (
  overrides: Partial<Extract<SevenZipParsedNextHeader, { kind: "encoded" }>> = {}
): Extract<SevenZipParsedNextHeader, { kind: "encoded" }> => ({
  kind: "encoded",
  hasEncryptedHeader: false,
  headerCoders: [],
  headerStreams: {
    packInfo: {
      packPos: PACK_POSITION_AT_ARCHIVE_START,
      numPackStreams: BigInt(SINGLE_STREAM_COUNT),
      packSizes: [BigInt(PACKED_EMPTY_HEADER.byteLength)],
      packCrcs: []
    },
    unpackInfo: {
      external: false,
      folders: [{
        coders: [{
          methodId: SEVENZIP_LZMA_METHOD_ID,
          inStreams: SINGLE_STREAM_COUNT,
          outStreams: SINGLE_STREAM_COUNT,
          propertiesSize: LZMA_PROPERTIES.length,
          propertyBytes: LZMA_PROPERTIES,
          properties: null
        }],
        totalInStreams: SINGLE_STREAM_COUNT,
        totalOutStreams: SINGLE_STREAM_COUNT,
        bindPairs: [],
        packedStreams: [],
        numPackedStreams: SINGLE_STREAM_COUNT,
        numBindPairs: NO_BIND_PAIRS
      }],
      unpackSizes: [[EMPTY_HEADER_UNPACK_SIZE]]
    }
  },
  ...overrides
});

const createHeaderFile = (packedBytes = PACKED_EMPTY_HEADER): MockFile => {
  const bytes = new Uint8Array(SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER + packedBytes.byteLength);
  bytes.set(packedBytes, SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER);
  return new MockFile(bytes, "encoded.7z");
};

void test("decodeEncodedHeader decodes a single non-encrypted LZMA header stream", async () => {
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(createHeaderFile(), createEncodedHeader(), issues);

  assert.equal(decoded?.kind, "header");
  assert.deepEqual(issues, []);
});

const lzma2Header = (): Extract<SevenZipParsedNextHeader, { kind: "encoded" }> => {
  const parsed = createEncodedHeader();
  const coder = parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!;
  coder.methodId = "21";
  coder.propertyBytes = [0];
  coder.propertiesSize = 1;
  parsed.headerStreams.packInfo!.packSizes = [6n];
  return parsed;
};

void test("LZMA2 uncompressed chunk can encode a 7z header", async () => {
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0)), lzma2Header(), issues);

  assert.deepEqual(decoded, { kind: "header", sections: {} });
  assert.deepEqual(issues, []);
});

void test("LZMA2 header missing the final control is reported as a visible issue", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.packInfo!.packSizes = [5n];
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0)), parsed, issues);

  assert.equal(decoded, null);
  assert.match(issues[0]!, /Encoded 7z header decode failed: LZMA SDK error/);
});

void test("LZMA2 header with trailing input is rejected", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.packInfo!.packSizes = [7n];
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0, 42)), parsed, issues);

  assert.equal(decoded, null);
  assert.match(issues[0]!, /unconsumed input/);
});

void test("LZMA2 header properties are validated before decoding", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!.propertyBytes = [41];
  const issues: string[] = [];

  assert.equal(await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0)), parsed, issues), null);
  assert.match(issues[0]!, /LZMA2 coder properties are invalid/);
});

void test("LZMA2 header rejects an incorrect unpacked CRC", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.unpackInfo!.folderCrcs = { digests: [{ index: 0, crc: 0 }] };
  const issues: string[] = [];

  assert.equal(await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0)), parsed, issues), null);
  assert.match(issues[0]!, /header CRC/);
});

void test("LZMA2 header accepts its correct unpacked CRC", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.unpackInfo!.folderCrcs = {
    digests: [{ index: 0, crc: crc32(Uint8Array.of(1, 0)) }]
  };
  const issues: string[] = [];

  assert.equal((await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0)), parsed, issues))?.kind, "header");
  assert.deepEqual(issues, []);
});

void test("LZMA2 header rejects an incorrect packed CRC", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.packInfo!.packCrcs = [{ index: 0, crc: 0 }];
  const issues: string[] = [];

  assert.equal(await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0)), parsed, issues), null);
  assert.match(issues[0]!, /packed.*CRC/);
});

void test("LZMA2 header rejects a coder declaring multiple inputs", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!.inStreams = 2;
  const issues: string[] = [];

  assert.equal(await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 1, 0, 0)), parsed, issues), null);
  assert.match(issues[0]!, /unsupported stream layout/);
});

for (const [name, change] of [
  ["two folders", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders.push(parsed.headerStreams.unpackInfo!.folders[0]!)],
  ["no coder", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders[0]!.coders.splice(0)],
  ["two coders", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders[0]!.coders.push(
      parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!)],
  ["multiple packed streams", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders[0]!.numPackedStreams = 2],
  ["bind pairs", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders[0]!.numBindPairs = 1],
  ["two coder outputs", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!.outStreams = 2],
  ["unsupported method", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!.methodId = "00"],
  ["two packed sizes", (parsed: ReturnType<typeof lzma2Header>) =>
    parsed.headerStreams.packInfo!.packSizes.push(6n)]
] as const) {
  void test(`LZMA2 header rejects unsupported layout: ${name}`, async () => {
    const parsed = lzma2Header();
    change(parsed);
    const issues: string[] = [];

    assert.equal(await decodeEncodedHeader(createHeaderFile(), parsed, issues), null);
    assert.match(issues[0]!, /unsupported stream layout/);
  });
}

for (const [packPos, packSize, error] of [
  [-1n, 6n, /file bounds/], [0n, -1n, /file bounds/],
  [2n ** 54n, 6n, /supported range/], [0n, 2n ** 54n, /supported range/]
] as const) {
  void test(`LZMA2 header rejects packed range ${packPos}:${packSize}`, async () => {
    const parsed = lzma2Header();
    parsed.headerStreams.packInfo!.packPos = packPos;
    parsed.headerStreams.packInfo!.packSizes = [packSize];
    const issues: string[] = [];

    assert.equal(await decodeEncodedHeader(createHeaderFile(), parsed, issues), null);
    assert.match(issues[0]!, error);
  });
}

void test("LZMA2 header accepts the correct packed CRC, ignoring other digest indexes", async () => {
  const parsed = lzma2Header();
  const packed = Uint8Array.of(1, 0, 1, 1, 0, 0);
  parsed.headerStreams.packInfo!.packCrcs = [
    { index: 1, crc: 0 }, { index: 0, crc: crc32(packed) }
  ];
  parsed.headerStreams.unpackInfo!.folderCrcs = { digests: [{ index: 1, crc: 0 }] };
  const issues: string[] = [];

  assert.equal((await decodeEncodedHeader(createHeaderFile(packed), parsed, issues))?.kind, "header");
  assert.deepEqual(issues, []);
});

void test("LZMA2 decoded header must begin with the Header marker", async () => {
  const issues: string[] = [];

  assert.equal(await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(1, 0, 1, 9, 0, 0)), lzma2Header(), issues), null);
  assert.deepEqual(issues, ["Decoded 7z header did not start with a Header marker."]);
});

void test("LZMA2 header respects its nonzero position within packed streams", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.packInfo!.packPos = 1n;
  const issues: string[] = [];

  assert.equal((await decodeEncodedHeader(
    createHeaderFile(Uint8Array.of(42, 1, 0, 1, 1, 0, 0)), parsed, issues))?.kind, "header");
  assert.deepEqual(issues, []);
});

void test("an empty packed range reaches the decoder and reports input EOF", async () => {
  const parsed = lzma2Header();
  parsed.headerStreams.packInfo!.packSizes = [0n];
  const issues: string[] = [];

  assert.equal(await decodeEncodedHeader(createHeaderFile(), parsed, issues), null);
  assert.match(issues[0]!, /decode failed: LZMA SDK error/);
});

void test("decodeEncodedHeader reports encrypted encoded headers", async () => {
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(
    createHeaderFile(),
    createEncodedHeader({ hasEncryptedHeader: true }),
    issues
  );

  assert.equal(decoded, null);
  assert.deepEqual(issues, ["Encoded 7z header is encrypted; unable to decode."]);
});

void test("decodeEncodedHeader reports unsupported encoded stream layouts", async () => {
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(
    createHeaderFile(),
    createEncodedHeader({ headerStreams: {} }),
    issues
  );

  assert.equal(decoded, null);
  assert.deepEqual(issues, ["Encoded 7z header uses an unsupported stream layout."]);
});

void test("decodeEncodedHeader reports packed streams outside file bounds", async () => {
  const issues: string[] = [];
  const decoded = await decodeEncodedHeader(
    new MockFile(new Uint8Array(SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER), "short.7z"),
    createEncodedHeader(),
    issues
  );

  assert.equal(decoded, null);
  assert.deepEqual(issues, ["Encoded 7z header packed stream lies outside the file bounds."]);
});

void test("decodeEncodedHeader reports LZMA decode failures as issues", async () => {
  const issues: string[] = [];
  const parsed = createEncodedHeader();
  parsed.headerStreams.unpackInfo!.folders[0]!.coders[0]!.propertyBytes = [0x5d];
  const decoded = await decodeEncodedHeader(createHeaderFile(), parsed, issues);

  assert.equal(decoded, null);
  assert.match(issues[0] || "", /Encoded 7z header decode failed/);
});
