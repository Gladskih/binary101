"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { calculateSectionEntropies } from "../../../analyzers/section-entropy.js";
import { MockFile } from "../../helpers/mock-file.js";

class SliceTrackingBlob extends Blob {
  sliceCalls = 0;
  override slice(start?: number, end?: number, contentType?: string): Blob {
    this.sliceCalls += 1;
    return super.slice(start, end, contentType);
  }
}

void test("calculateSectionEntropies calculates each complete section range", async () => {
  const file = new MockFile(Uint8Array.of(0xaa, 0xaa, 0xaa, 0xaa, 0, 0, 0xff, 0xff));

  const entropies = await calculateSectionEntropies(file, [
    { pointerToRawData: 0, sizeOfRawData: 4 },
    { pointerToRawData: 4, sizeOfRawData: 4 }
  ]);

  assert.deepEqual(entropies, [0, 1]);
});

void test("calculateSectionEntropies reports unavailable malformed ranges", async () => {
  const file = new SliceTrackingBlob([new Uint8Array(8)]);

  const entropies = await calculateSectionEntropies(file, [
    { pointerToRawData: 0, sizeOfRawData: 0 },
    { pointerToRawData: 8, sizeOfRawData: 1 },
    { pointerToRawData: 6, sizeOfRawData: 3 },
    { pointerToRawData: -1, sizeOfRawData: 1 },
    { pointerToRawData: 0.5, sizeOfRawData: 1 },
    { pointerToRawData: 0, sizeOfRawData: -1 },
    { pointerToRawData: 0, sizeOfRawData: 1.5 },
    { pointerToRawData: 0, sizeOfRawData: Number.NaN },
    { pointerToRawData: Number.MAX_SAFE_INTEGER, sizeOfRawData: 1 }
  ]);

  assert.deepEqual(entropies, Array.from({ length: 9 }, () => null));
  assert.equal(file.sliceCalls, 0);
});

void test("calculateSectionEntropies handles a one-byte section", async () => {
  const file = new MockFile(Uint8Array.of(0xff));

  const entropies = await calculateSectionEntropies(file, [
    { pointerToRawData: 0, sizeOfRawData: 1 }
  ]);

  assert.deepEqual(entropies, [0]);
});

void test("calculateSectionEntropies rejects a short section stream", async () => {
  const shortStreamFile = {
    size: 4,
    slice: () => ({ stream: () => new Blob([Uint8Array.of(0)]).stream() })
  } as unknown as Blob;

  const entropies = await calculateSectionEntropies(shortStreamFile, [
    { pointerToRawData: 0, sizeOfRawData: 4 }
  ]);

  assert.deepEqual(entropies, [null]);
});

void test("calculateSectionEntropies releases its section stream reader", async () => {
  let readCount = 0;
  let released = false;
  const file = {
    size: 1,
    slice: () => ({
      stream: () => ({
        getReader: () => ({
          read: async () => {
            readCount += 1;
            return readCount === 1
              ? { done: false, value: Uint8Array.of(0xff) }
              : { done: true, value: undefined };
          },
          releaseLock: () => { released = true; }
        })
      })
    })
  } as unknown as Blob;

  const entropies = await calculateSectionEntropies(file, [
    { pointerToRawData: 0, sizeOfRawData: 1 }
  ]);

  assert.deepEqual(entropies, [0]);
  assert.equal(released, true);
});
