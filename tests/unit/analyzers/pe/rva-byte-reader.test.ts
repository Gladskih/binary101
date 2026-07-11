"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readMappedRvaPrefix } from "../../../../analyzers/pe/rva-byte-reader.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("readMappedRvaPrefix joins adjacent RVAs with noncontiguous raw offsets", async () => {
  const bytes = new Uint8Array(0x40);
  bytes.set([1, 2], 0x10);
  bytes.set([3, 4], 0x30);
  const view = await readMappedRvaPrefix(
    new MockFile(bytes),
    0x1000,
    4,
    rva => rva < 0x1002 ? 0x10 + rva - 0x1000 : 0x30 + rva - 0x1002
  );
  assert.deepEqual(Array.from(new Uint8Array(view.buffer)), [1, 2, 3, 4]);
});

void test("readMappedRvaPrefix returns only the readable mapped prefix", async () => {
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  const view = await readMappedRvaPrefix(
    new MockFile(bytes), 0x2000, 4,
    rva => rva < 0x2002 ? rva - 0x2000 : null
  );
  assert.deepEqual(Array.from(new Uint8Array(view.buffer)), [1, 2]);
});

void test("readMappedRvaPrefix rejects invalid ranges and offsets", async () => {
  const file = new MockFile(Uint8Array.from([1, 2, 3, 4]));
  let invalidReadCount = 0;
  const guardedReader = {
    size: file.size,
    read: (offset: number, size: number) => {
      invalidReadCount += 1;
      return file.read(offset, size);
    },
    readBytes: (offset: number, size: number) => file.readBytes(offset, size)
  };
  const invalidRva = await readMappedRvaPrefix(file, -1, 1, () => 0);
  const unsafeRva = await readMappedRvaPrefix(file, Number.NaN, 1, () => 0);
  const invalidSize = await readMappedRvaPrefix(file, 0, 0, rva => rva);
  const unsafeSize = await readMappedRvaPrefix(file, 0, 1.5, () => 0);
  const invalidOffset = await readMappedRvaPrefix(file, 0, 2, () => Number.NaN);
  const negativeOffset = await readMappedRvaPrefix(guardedReader, 0, 2, () => -1);
  const endOffset = await readMappedRvaPrefix(guardedReader, 0, 2, () => file.size);
  assert.equal(invalidRva.byteLength, 0);
  assert.equal(unsafeRva.byteLength, 0);
  assert.equal(invalidSize.byteLength, 0);
  assert.equal(unsafeSize.byteLength, 0);
  assert.equal(invalidOffset.byteLength, 0);
  assert.equal(negativeOffset.byteLength, 0);
  assert.equal(endOffset.byteLength, 0);
  assert.equal(invalidReadCount, 0);
});

void test("readMappedRvaPrefix stops at the PE RVA limit and short file reads", async () => {
  const file = new MockFile(Uint8Array.from([1, 2, 3, 4]));
  const atLimit = await readMappedRvaPrefix(
    file, 0xffff_fffe, 4, rva => rva - 0xffff_fffe
  );
  let readCount = 0;
  const short = await readMappedRvaPrefix(
    {
      size: 8,
      read: async () => {
        readCount += 1;
        return new DataView(Uint8Array.from(readCount === 1 ? [1] : [3, 4]).buffer);
      },
      readBytes: async () => Uint8Array.from([1])
    },
    0,
    4,
    rva => rva < 2 ? rva : rva + 2
  );
  assert.deepEqual(Array.from(new Uint8Array(atLimit.buffer)), [1, 2]);
  assert.deepEqual(Array.from(new Uint8Array(short.buffer)), [1]);
  assert.equal(readCount, 1);
});
