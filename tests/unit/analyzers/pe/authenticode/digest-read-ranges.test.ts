"use strict";

import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { computePeAuthenticodeDigestBestEffort } from "../../../../../analyzers/pe/authenticode/digest.js";
import {
  createAuthenticodeReadTrackingFixture,
  listBestEffortAuthenticodeHashRangesWithoutSecurityEntry
} from "../../../../fixtures/pe-authenticode-fixtures.js";

const SHA_256_BYTE_LENGTH = 32;

void test("computePeAuthenticodeDigest rejects readers without readInto", async () => {
  const fixture = createAuthenticodeReadTrackingFixture(256);
  delete fixture.reader.readInto;

  await assert.rejects(
    computePeAuthenticodeDigestBestEffort(
      fixture.reader,
      { optOff: 0, ddStartRel: 100, dataDirs: [] },
      undefined,
      "SHA-256"
    ),
    /does not support direct range reads/
  );
  assert.deepEqual(fixture.requests, []);
});

void test("computePeAuthenticodeDigest writes hash ranges through readInto", async () => {
  const readerSize = 256;
  const ranges = listBestEffortAuthenticodeHashRangesWithoutSecurityEntry(readerSize);
  const fixture = createAuthenticodeReadTrackingFixture(readerSize);
  const streamedRequests: Array<{ offset: number; length: number }> = [];
  fixture.reader.readInto = async (offset, destination) => {
    streamedRequests.push({ offset, length: destination.byteLength });
    destination.fill(0);
    return destination;
  };
  let digestInputSize = 0;
  const slice = mock.method(Uint8Array.prototype, "slice");

  try {
    await computePeAuthenticodeDigestBestEffort(
      fixture.reader,
      { optOff: 0, ddStartRel: 100, dataDirs: [] },
      undefined,
      "SHA-256",
      async (_algorithm, data) => {
        digestInputSize = data.byteLength;
        return new Uint8Array(SHA_256_BYTE_LENGTH).buffer;
      }
    );

    assert.deepEqual(streamedRequests, ranges.map(range => ({
      offset: range.start,
      length: range.end - range.start
    })));
    assert.deepEqual(fixture.requests, []);
    assert.equal(digestInputSize, readerSize - Uint32Array.BYTES_PER_ELEMENT);
    assert.equal(slice.mock.callCount(), 0);
  } finally {
    slice.mock.restore();
  }
});

void test("computePeAuthenticodeDigest trims its input after a short readInto", async () => {
  const readerSize = 256;
  const maximumReturnedBytes = 16;
  const ranges = listBestEffortAuthenticodeHashRangesWithoutSecurityEntry(readerSize);
  const { reader, requests } = createAuthenticodeReadTrackingFixture(readerSize, maximumReturnedBytes);
  let digestInputSize = 0;

  await computePeAuthenticodeDigestBestEffort(
    reader,
    { optOff: 0, ddStartRel: 100, dataDirs: [] },
    undefined,
    "SHA-256",
    async (_algorithm, data) => {
      digestInputSize = data.byteLength;
      return new Uint8Array(SHA_256_BYTE_LENGTH).buffer;
    }
  );

  assert.equal(requests.length, ranges.length);
  assert.equal(digestInputSize, ranges.length * maximumReturnedBytes);
});
