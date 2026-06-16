"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeEncodedHeader } from "../../../../analyzers/sevenz/encoded-header.js";
import { SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER } from "../../../../analyzers/sevenz/layout.js";
import { SEVENZIP_LZMA_METHOD_ID } from "../../../../analyzers/sevenz/method-ids.js";
import type { SevenZipParsedNextHeader } from "../../../../analyzers/sevenz/types.js";
import { MockFile } from "../../../helpers/mock-file.js";

const EMPTY_HEADER_UNPACK_SIZE = 2n;
const PACK_POSITION_AT_ARCHIVE_START = 0n;
const SINGLE_STREAM_COUNT = 1;
const NO_BIND_PAIRS = 0;
// 7z LZMA coder properties for lc=3, lp=0, pb=2 and a 64 KiB dictionary.
// https://www.7-zip.org/sdk.html
const LZMA_PROPERTIES = [0x5d, 0x00, 0x00, 0x01, 0x00];
// Raw LZMA stream fixture that decodes to a minimal Header payload [0x01, 0x00].
// The enclosing lzma_alone header is built by lzma.ts from separate 7z properties.
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
  const decoded = await decodeEncodedHeader(
    createHeaderFile(),
    createEncodedHeader({
      headerStreams: {
        ...createEncodedHeader().headerStreams,
        unpackInfo: {
          external: false,
          folders: [{
            ...createEncodedHeader().headerStreams.unpackInfo!.folders[0]!,
            coders: [{
              ...createEncodedHeader().headerStreams.unpackInfo!.folders[0]!.coders[0]!,
              propertyBytes: [0x5d]
            }]
          }],
          unpackSizes: [[EMPTY_HEADER_UNPACK_SIZE]]
        }
      }
    }),
    issues
  );

  assert.equal(decoded, null);
  assert.match(issues[0] || "", /Encoded 7z header decode failed/);
});
